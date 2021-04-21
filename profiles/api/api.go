package api

// Some useful imports :^).
import (
	"database/sql"
	_ "encoding/json"
	_ "log"
	"net/http"

	"github.com/gorilla/mux"
)

// Like before, think about what methods would be appropriate for these routes.
func RegisterRoutes(router *mux.Router, db *sql.DB) {
	router.HandleFunc("/api/profile/{uuid}", getProfile(db)).Methods( /* YOUR CODE HERE */ )
	router.HandleFunc("/api/profile/{uuid}", updateProfile(db)).Methods( /* YOUR CODE HERE */ )
}

// Retrieves a Profile from the users database and returns it in the response as a JSON.
func getProfile(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Obtain the uuid from the url path and store it in a `uuid` variable
		// (Hint: mux.Vars())

		// Query the database and store a matching Profile into a variable. What errors might go wrong here?

		// Encode fetched data as JSON and serve to client

	}
}

func updateProfile(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Obtain the requested uuid from the url path and store it in a `uuid` variable

		// Obtain the UUID from the cookie. See jwt.go. What errors should you check for?
		// (Hint: What if the UUID from the cookie doesn't match the UUID in the request?)

		// Decode the Request Body's JSON data into a profile variable. Make sure to check for errors!

		// Insert the profile data into the users table.
		// (Hint: Make sure to use REPLACE INTO)
	}
}
