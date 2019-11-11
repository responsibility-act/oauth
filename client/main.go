package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"text/tabwriter"
	"time"

	"github.com/jpgriffo/oauth/client/goth/aps"
	"github.com/kataras/iris/v12"
	"github.com/kataras/iris/v12/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/gplus"
)

// UserNotLoggedIn - Return in Json format user not logged message
func UserNotLoggedIn() map[string]string {
	return map[string]string{"code": "401", "message": "Please login into the platform"}
}

// StandardErrorWithStatusCode - Return in Json format standar error message
func StandardErrorWithStatusCode(code int, errorMessage error) map[string]string {
	return map[string]string{"code": http.StatusText(code), "message": errorMessage.Error()}
}

func main() {
	api := iris.New()
	sessManager := sessions.New(sessions.Config{
		Cookie:  "irissessionid",
		Expires: 2 * time.Hour,
	})
	api.Use(sessManager.Handler())

	goth.UseProviders(
		aps.New("bawdy-reindeers-14-56dd2bcc2ba94", "6454acedc7024fdfa743c5407da7ad44", "http://localhost:3000/auth/aps/callback"),
		gplus.New("72983246488-upvsod3t92stf9o9ojvqvqrip0t3anln.apps.googleusercontent.com", "M8D_euTcQ9WC2NJdTwVqwX5R", "http://localhost:3000/auth/gplus/callback"),
	)

	api.Get("/", func(ctx iris.Context) {
		session := sessions.Get(ctx)
		user := session.Get("user")
		if user == nil {
			ctx.StatusCode(iris.StatusUnauthorized)
			ctx.JSON(UserNotLoggedIn())
			return
		}

		ctx.JSON(user.(goth.User))
	})

	api.Get("/auth/{provider}", func(ctx iris.Context) {
		BeginAuthHandler(ctx)
	})

	api.Get("/auth/{provider}/callback", func(ctx iris.Context) {
		user, err := CompleteUserAuth(ctx)
		if err != nil {
			ctx.StatusCode(iris.StatusUnauthorized)
			ctx.JSON(StandardErrorWithStatusCode(iris.StatusUnauthorized, err))
			return
		}
		sessions.Get(ctx).Set("user", user)
		ctx.Redirect("/", iris.StatusOK)
	})

	api.Get("/login", func(c iris.Context) {
		c.Writef("You are session with ID: %s", sessions.Get(c).ID())
	})

	api.Get("/logout", func(ctx iris.Context) {
		//destroy, removes the entire session and cookie
		sessions.Get(ctx).Destroy()
		ctx.Redirect("/", iris.StatusAccepted)
	})

	w := tabwriter.NewWriter(os.Stdout, 15, 1, 3, ' ', 0)

	fmt.Fprintf(w, "Configured Routes:\n")
	fmt.Fprintf(w, "\tNAME\tMETHOD\tPATH\n")

	for _, route := range api.GetRoutesReadOnly() {
		fmt.Fprintf(w, "\t%s\t%s\t%s\n", route.Name(), route.Method(), route.Path())
	}
	w.Flush()

	api.Run(iris.Addr(":3000"), iris.WithoutServerError(iris.ErrServerClosed))
}

/*
BeginAuthHandler is a convenience handler for starting the authentication process.
It expects to be able to get the name of the provider from the query parameters
as either "provider" or ":provider".
BeginAuthHandler will redirect the user to the appropriate authentication end-point
for the requested provider.
See https://github.com/markbates/goth/examples/main.go to see this in action.
*/
func BeginAuthHandler(ctx iris.Context) {
	url, err := GetAuthURL(ctx)
	if err != nil {
		ctx.StatusCode(iris.StatusInternalServerError)
		ctx.JSON(StandardErrorWithStatusCode(iris.StatusInternalServerError, err))
		return
	}

	ctx.Redirect(url, iris.StatusTemporaryRedirect)
}

/*
GetAuthURL starts the authentication process with the requested provided.
It will return a URL that should be used to send users to.
It expects to be able to get the name of the provider from the query parameters
as either "provider" or ":provider" or from the context's value of "provider" key.
I would recommend using the BeginAuthHandler instead of doing all of these steps
yourself, but that's entirely up to you.
*/
func GetAuthURL(ctx iris.Context) (string, error) {
	providerName, err := GetProviderName(ctx)
	if err != nil {
		return "", err
	}

	provider, err := goth.GetProvider(providerName)
	if err != nil {
		return "", err
	}
	sess, err := provider.BeginAuth(SetState(ctx))
	if err != nil {
		return "", err
	}

	url, err := sess.GetAuthURL()
	if err != nil {
		return "", err
	}
	session := sessions.Get(ctx)
	session.Set(providerName, sess.Marshal())
	return url, nil
}

// These are some function helpers that you may use if you want

// GetProviderName is a function used to get the name of a provider
// for a given request. By default, this provider is fetched from
// the URL query string. If you provide it in a different way,
// assign your own function to this variable that returns the provider
// name for your request.
var GetProviderName = func(ctx iris.Context) (string, error) {
	// try to get it from the url param "provider"
	if p := ctx.URLParam("provider"); p != "" {
		return p, nil
	}

	// try to get it from the url PATH parameter "{provider} or :provider or {provider:string} or {provider:alphabetical}"
	if p := ctx.Params().Get("provider"); p != "" {
		return p, nil
	}

	// try to get it from context's per-request storage
	if p := ctx.Values().GetString("provider"); p != "" {
		return p, nil
	}
	// if not found then return an empty string with the corresponding error
	return "", errors.New("you must select a provider")
}

// SetState sets the state string associated with the given request.
// If no state string is associated with the request, one will be generated.
// This state is sent to the provider and can be retrieved during the
// callback.
var SetState = func(ctx iris.Context) string {
	state := ctx.URLParam("state")
	if len(state) > 0 {
		return state
	}

	return "state"
}

// GetState gets the state returned by the provider during the callback.
// This is used to prevent CSRF attacks, see
// http://tools.ietf.org/html/rfc6749#section-10.12
var GetState = func(ctx iris.Context) string {
	return ctx.URLParam("state")
}

/*
CompleteUserAuth does what it says on the tin. It completes the authentication
process and fetches all of the basic information about the user from the provider.
It expects to be able to get the name of the provider from the query parameters
as either "provider" or ":provider".
See https://github.com/markbates/goth/examples/main.go to see this in action.
*/
var CompleteUserAuth = func(ctx iris.Context) (goth.User, error) {
	providerName, err := GetProviderName(ctx)
	if err != nil {
		return goth.User{}, err
	}

	provider, err := goth.GetProvider(providerName)
	if err != nil {
		return goth.User{}, err
	}
	session := sessions.Get(ctx)
	value := session.GetString(providerName)
	if value == "" {
		return goth.User{}, errors.New("session value for " + providerName + " not found")
	}

	sess, err := provider.UnmarshalSession(value)
	if err != nil {
		return goth.User{}, err
	}

	user, err := provider.FetchUser(sess)
	if err == nil {
		// user can be found with existing session data
		return user, err
	}

	// get new token and retry fetch
	_, err = sess.Authorize(provider, ctx.Request().URL.Query())
	if err != nil {
		return goth.User{}, err
	}

	session.Set(providerName, sess.Marshal())
	return provider.FetchUser(sess)
}
