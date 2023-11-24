// Package model ...
package model

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/google"
)

// EnvKind ...
type EnvKind string

// OAuth2Provider ...
type OAuth2Provider string

const (
	EnvDev  EnvKind = "dev"  // EnvDev ...
	EnvProd EnvKind = "prod" // EnvProd ...

	OAuth2Google   OAuth2Provider = "google"   // OAuth2Google ...
	OAuth2Facebook OAuth2Provider = "facebook" // OAuth2Facebook ...
)

// OAuth2Handler ...
type OAuth2Handler struct {
	Config      map[EnvKind]*oauth2.Config
	UserDataURL string
	CallbackFn  fiber.Handler `json:"-"`
	LoginFn     fiber.Handler `json:"-"`
}

// GlobalOAuth2Handler ...
var GlobalOAuth2Handler = map[OAuth2Provider]*OAuth2Handler{
	OAuth2Google: newOAuth2Handler(OAuth2Google, &OAuth2Handler{
		Config: map[EnvKind]*oauth2.Config{
			EnvDev: {
				Scopes: []string{
					"https://www.googleapis.com/auth/userinfo.email",
					"https://www.googleapis.com/auth/userinfo.profile",
				},
				Endpoint: google.Endpoint,
			},
			EnvProd: {
				Scopes: []string{
					"https://www.googleapis.com/auth/userinfo.email",
					"https://www.googleapis.com/auth/userinfo.profile",
				},
				Endpoint: google.Endpoint,
			},
		},
		UserDataURL: "https://www.googleapis.com/oauth2/v3/userinfo?access_token=%s",
	}),
	OAuth2Facebook: newOAuth2Handler(OAuth2Facebook, &OAuth2Handler{
		Config: map[EnvKind]*oauth2.Config{
			EnvDev: {
				Scopes: []string{
					"email",
					"openid", // use id_token
				},
				Endpoint: facebook.Endpoint,
			},
			EnvProd: {
				Scopes: []string{
					"email",
					"openid", // use id_token
				},
				Endpoint: facebook.Endpoint,
			},
		},
		UserDataURL: "https://graph.facebook.com/v3.2/me?access_token=%s",
	}),
}

var HostName = map[EnvKind]string{}

func getEnv(envKind EnvKind, varName string) string {
        return os.Getenv(
                strings.ToUpper(
                        fmt.Sprintf("%s_%s", envKind, varName),
                ),
        )
}

func getProviderEnv(envKind EnvKind, provider OAuth2Provider, varName string) string {
	return os.Getenv(
		strings.ToUpper(
			fmt.Sprintf("%s_%s_%s", envKind, provider, varName),
		),
	)
}

func getLoginFn(provider OAuth2Provider, handler *OAuth2Handler) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var envKind EnvKind
		switch c.Hostname() {
			case HostName[EnvDev]:
				envKind = EnvDev
			case HostName[EnvProd]:
				envKind = EnvProd
			default:
				return fmt.Errorf("unknow env from domain(%s)", c.Hostname())
		}
		url := handler.Config[envKind].AuthCodeURL("randomstate")
		c.Status(fiber.StatusSeeOther)
		err := c.Redirect(url)
		if err != nil {
			return err
		}
		return c.JSON(url)
	}
}

const (
	facebookBatchURL             = `https://graph.facebook.com/v18.0/?batch=%s&include_headers=false&access_token=%s` // facebookBatchURL 'batch' inject need be a array facebookBatchRequest json and uri encode.
	facebookUserInfoRelativeURL  = `me?fields=name,email`                                                             // facebookUserInfoRelativeURL ...
	facebookTokenInfoRelativeURL = `debug_token?input_token=%s`                                                       // facebookTokenInfoRelativeURL input_token == accessToken, cant skip
)
// facebookBatchRequest batch API request, it need be array and URI encode.
type facebookBatchRequest struct {
	Method      string `json:"method"`
	RelativeURL string `json:"relative_url"`
}

func getCallbackFn(provider OAuth2Provider, handler *OAuth2Handler) fiber.Handler {
	return func(c *fiber.Ctx) error {
		result := []string{}

		var envKind EnvKind
                switch c.Hostname() {
                        case HostName[EnvDev]:
                                envKind = EnvDev
                        case HostName[EnvProd]:
                                envKind = EnvProd
                        default:
                                return fmt.Errorf("unknow env from domain(%s)", c.Hostname())
                }

		state := c.Query("state")
		if state != "randomstate" {
			return c.SendString("States don't Match!!")
		}

		code := c.Query("code")
		fmt.Println(code)

		token, err := handler.Config[envKind].Exchange(context.Background(), code)
		if err != nil {
			return c.SendString("Code-Token Exchange Failed")
		}
		fmt.Println(token)

		tokenJson , err := json.MarshalIndent(token, "", "    ")
		if err != nil {
			return c.SendString("marshal token failed")
		}
		result = append(result, "[AccessToken]", string(tokenJson))

		resp, err := http.Get(fmt.Sprintf(handler.UserDataURL, token.AccessToken))
		if err != nil {
			return c.SendString("User Data Fetch Failed")
		}
		defer resp.Body.Close()
		fmt.Println(resp)

		userData, err := io.ReadAll(resp.Body)
		if err != nil {
			return c.SendString("resp body read failed")
		}
		fmt.Println(string(userData))
		result = append(result, "[UserData]", string(userData))

		if provider == OAuth2Google{
			idTokenInf := token.Extra("id_token")
			idToken, ok := idTokenInf.(string)
			if !ok {
				return c.SendString("get id token failed")
			}
			result = append(result, "[GoogleIDToken]", idToken)
		}
		if provider == OAuth2Facebook{
			idTokenInf := token.Extra("id_token")
                        idToken, ok := idTokenInf.(string)
                        if !ok {
                                return c.SendString("get id token failed")
                        }
                        result = append(result, "[FacebookIDToken(need enable scopes openid)]", idToken)

			batchCmd := []facebookBatchRequest{{
				Method:      "GET",
				RelativeURL: facebookUserInfoRelativeURL,
			}, {
				Method:      "GET",
				RelativeURL: fmt.Sprintf(facebookTokenInfoRelativeURL, token.AccessToken),
			}}
			batchCmdB, err := json.Marshal(batchCmd)
			if err != nil {
				return c.SendString(fmt.Sprintf("marshal facebook userInfo err: %s", err.Error()))
			}
			fbClient := http.Client{}
			fbReq , err := http.NewRequest("POST", fmt.Sprintf(facebookBatchURL, url.QueryEscape(string(batchCmdB)), token.AccessToken), nil)
			if err != nil {
				return c.SendString(fmt.Sprintf("facebook client err: %s", err.Error()))
			}
			fbReq.Header.Set("Content-Type", "application/json")
			fbResp, err := fbClient.Do(fbReq)
			if err != nil {
				return c.SendString(fmt.Sprintf("get facebook userInfo err: %s", err.Error()))
			}
			defer fbResp.Body.Close()
			fmt.Println(fbResp)

			fbUserData, err := io.ReadAll(fbResp.Body)
	                if err != nil {
        	                return c.SendString("facebook userData read failed")
              		}
	                fmt.Println(string(userData))

			result = append(result, "[FacebookUserData]", string(fbUserData))
		}

		return c.SendString(strings.Join(result, "\n"))
	}
}

var envLoaded = false

func newOAuth2Handler(provider OAuth2Provider, handler *OAuth2Handler) *OAuth2Handler {
	if !envLoaded {
		if err := godotenv.Load(".env"); err != nil {
			panic(fmt.Sprintf("Some error occured. Err: %s", err))
		}
		envLoaded = true
	}

	for _, envKind := range []EnvKind{EnvDev, EnvProd} {
		config, ok := handler.Config[envKind]
		if !ok {
			panic(fmt.Sprintf("no provider(%s) config at env(%s)", provider, envKind))
		}
		switch envKind {
		case EnvDev, EnvProd:
		default:
			panic("newOAuth2Handler : unknow envKind")
		}		
		HostName[envKind] = getEnv(envKind, "HOST")
		envHostName := HostName[envKind]
                config.RedirectURL = fmt.Sprintf("https://%s/callback/%s", envHostName, provider)
		config.ClientID = getProviderEnv(envKind, provider, "CLIENT_ID")
		config.ClientSecret = getProviderEnv(envKind, provider, "CLIENT_SECRET")
		handler.Config[envKind] = config
	}
	handler.LoginFn = getLoginFn(provider, handler)
	handler.CallbackFn = getCallbackFn(provider, handler)

	return handler
}
