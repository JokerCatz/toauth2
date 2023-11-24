// Package main ...
package main

import (
	"encoding/json"
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/jokercatz/toauth2/model"
)

func main() {
	data, err := json.Marshal(model.GlobalOAuth2Handler)
	fmt.Printf("config: %s , %s\n", string(data), err)

	app := fiber.New()
	app.Static("/", "./public")

	for provider, handler := range model.GlobalOAuth2Handler {
		app.Get(fmt.Sprintf("/login/%s", provider), handler.LoginFn)
		app.Get(fmt.Sprintf("/callback/%s", provider), handler.CallbackFn)
	}

	if err := app.Listen(":80"); err != nil {
		panic(err)
	}
}
