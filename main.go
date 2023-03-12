package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"

	ldap "github.com/go-ldap/ldap/v3"
	hibp "github.com/mattevans/pwned-passwords"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	validator "github.com/go-playground/validator/v10"
	"github.com/trustelem/zxcvbn"
)

type ModifyPasswordForm struct {
	Username        string `form:"username" binding:"required,validusername"`
	CurrentPassword string `form:"currentPassword" binding:"required"`
	NewPassword1    string `form:"newPassword1" binding:"required,gte=8"`
	NewPassword2    string `form:"newPassword2" binding:"required,eqfield=NewPassword1"`
}

const UsernameRegex = "^[a-zA-Z][a-zA-Z\\d\\-_]+$"
const serverAddress = "ldaps://ank.chnet"

var roots = x509.NewCertPool()
var hibpClient = hibp.NewClient()

func main() {
	// Load LDAP CA root
	cert, err := ioutil.ReadFile("static/wisvch.crt")
	if err != nil {
		panic(err)
	}
	roots.AppendCertsFromPEM(cert)

	// Set up validators
	if v, ok := binding.Validator.Engine().(*validator.Validate); ok {
		v.RegisterStructValidation(modifyPasswordFormValidator, ModifyPasswordForm{})
		err := v.RegisterValidation("validusername", usernameValidator)
		if err != nil {
			panic(err)
		}
	} else {
		panic("validator engine not set up")
	}

	// Set up router
	r := gin.New()
	r.Use(gin.Recovery())
	r.LoadHTMLFiles("static/form.html")
	r.GET("/healthz", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	// Set up main routes
	g := r.Group("/password")
	g.Static("/assets", "static/assets")
	g.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "form.html", gin.H{})
	})
	g.POST("/", func(c *gin.Context) {
		var form ModifyPasswordForm
		if err := c.ShouldBindWith(&form, binding.FormPost); err == nil {
			err = modifyPassword(&form)
			// Esacpe the username for logging
			escapedUsername := fmt.Sprintf("%q", form.Username)

			if err != nil {
				log.Printf("password modify failure for %s: %v", escapedUsername, err)
				c.HTML(http.StatusOK, "form.html", gin.H{
					"username":        form.Username,
					"currentPassword": form.CurrentPassword,
					"errors":          []string{"Password could not be modified, is the current password correct?"},
				})
			} else {
				log.Printf("password modify success for %s", escapedUsername)
				c.HTML(http.StatusOK, "form.html", gin.H{
					"success": true,
				})
			}
		} else {
			var errors []string
			// Support password change requests from Userman2 that only set Username and CurrentPassword
			if form.NewPassword1 != "" && form.NewPassword2 != "" {
				errors = formatError(err)
			}
			c.HTML(http.StatusOK, "form.html", gin.H{
				"username":        form.Username,
				"currentPassword": form.CurrentPassword,
				"errors":          errors,
			})
		}
	})

	// Start server
	log.Fatal(r.Run())
}

func modifyPassword(form *ModifyPasswordForm) error {
	opts := ldap.DialWithTLSConfig(&tls.Config{RootCAs: roots})
	conn, err := ldap.DialURL(serverAddress, opts)
	if err != nil {
		return fmt.Errorf("could dial LDAP server: %w", err)
	}
	defer conn.Close()
	dn := fmt.Sprintf("uid=%s,ou=People,dc=ank,dc=chnet", ldap.EscapeFilter(form.Username))
	err = conn.Bind(dn, form.CurrentPassword)
	if err != nil {
		return err
	}
	passwordModifyRequest := ldap.NewPasswordModifyRequest(dn, form.CurrentPassword, form.NewPassword1)
	_, err = conn.PasswordModify(passwordModifyRequest)
	return err
}

func usernameValidator(fl validator.FieldLevel) bool {
	username := fl.Field().String()
	b, _ := regexp.MatchString(UsernameRegex, username)
	return b
}

func modifyPasswordFormValidator(sl validator.StructLevel) {
	form := sl.Current().Interface().(ModifyPasswordForm)
	s := zxcvbn.PasswordStrength(form.NewPassword1, []string{form.Username, form.CurrentPassword})
	if s.Score < 3 {
		sl.ReportError(form.NewPassword1, "NewPassword1", "", "weak", "")
		return
	}
	pwned, err := hibpClient.Compromised(form.NewPassword1)
	if err != nil {
		log.Printf("could not check hibp: %v", err)
		return
	}
	if pwned {
		sl.ReportError(form.NewPassword1, "NewPassword1", "", "pwned", "")
	}
}

func formatError(err error) []string {
	v := err.(validator.ValidationErrors)
	f := make([]string, 0)
	for _, e := range v {
		//log.Printf("e: %v", e)
		switch e.Field() {
		case "Username":
			f = append(f, "Username is invalid")
		case "CurrentPassword":
			f = append(f, "Current password is invalid")
		case "NewPassword1":
			switch e.Tag() {
			case "required":
				f = append(f, "New password is required")
			case "weak":
				f = append(f, "New password is too weak")
			case "pwned":
				f = append(f, "New password is compromised according to 'Have I Been Pwned'")
			}
		case "NewPassword2":
			f = append(f, "New passwords do not match")
		}
	}
	return f
}
