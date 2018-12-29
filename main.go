package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/mattevans/pwned-passwords"
	"github.com/trustelem/zxcvbn"
	"gopkg.in/go-playground/validator.v8"
	"gopkg.in/ldap.v3"
	"io/ioutil"
	"log"
	"net/http"
	"reflect"
	"regexp"
)

type ModifyPasswordForm struct {
	Username        string `form:"username" binding:"required,validusername"`
	CurrentPassword string `form:"currentPassword" binding:"required"`
	NewPassword1    string `form:"newPassword1" binding:"required,gte=8"`
	NewPassword2    string `form:"newPassword2" binding:"required,eqfield=NewPassword1"`
}

const UsernameRegex = "^[0-9a-z]+$"
const serverName = "ank.chnet"
const serverAddress = "ank.chnet:636"

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
		v.RegisterValidation("validusername", usernameValidator)
	}

	// Set up router
	r := gin.Default()
	r.LoadHTMLFiles("static/form.html")
	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{})
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
			if err != nil {
				log.Printf("password modify failure for %s: %v", form.Username, err)
				c.HTML(http.StatusOK, "form.html", gin.H{
					"username":        form.Username,
					"currentPassword": form.CurrentPassword,
					"errors":          []string{"Password could not be modified, is the current password correct?"},
				})
			} else {
				log.Printf("password modify success for %s", form.Username)
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
	r.Run()
}

func modifyPassword(form *ModifyPasswordForm) error {
	l, err := ldap.DialTLS("tcp", serverAddress, &tls.Config{ServerName: serverName, RootCAs: roots, InsecureSkipVerify: true})
	if err != nil {
		return err
	}
	defer l.Close()
	dn := fmt.Sprintf("uid=%s,ou=People,dc=ank,dc=chnet", form.Username)
	err = l.Bind(dn, form.CurrentPassword)
	if err != nil {
		return err
	}
	passwordModifyRequest := ldap.NewPasswordModifyRequest(dn, form.CurrentPassword, form.NewPassword1)
	_, err = l.PasswordModify(passwordModifyRequest)
	return err
}

func usernameValidator(v *validator.Validate, topStruct reflect.Value, currentStructOrField reflect.Value,
	field reflect.Value, fieldType reflect.Type, fieldKind reflect.Kind, param string) bool {
	username := field.String()
	b, _ := regexp.MatchString(UsernameRegex, username)
	return b
}

func modifyPasswordFormValidator(v *validator.Validate, sl *validator.StructLevel) {
	form := sl.CurrentStruct.Interface().(ModifyPasswordForm)
	s := zxcvbn.PasswordStrength(form.NewPassword1, []string{form.Username, form.CurrentPassword})
	if s.Score < 3 {
		sl.ReportError(reflect.ValueOf(form.NewPassword1), "NewPassword1", "", "weak")
		return
	}
	pwned, err := hibpClient.Pwned.Compromised(form.NewPassword1)
	if err != nil {
		log.Printf("could not check hibp: %v", err)
		return
	}
	if pwned {
		sl.ReportError(reflect.ValueOf(form.NewPassword1), "NewPassword1", "", "pwned")
	}
}

func formatError(err error) []string {
	v := err.(validator.ValidationErrors)
	f := make([]string, 0)
	for _, e := range v {
		//log.Printf("e: %v", e)
		switch e.Field {
		case "Username":
			f = append(f, "Username is invalid")
		case "CurrentPassword":
			f = append(f, "Current password is invalid")
		case "NewPassword1":
			switch e.Tag {
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
