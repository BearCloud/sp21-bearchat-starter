package api

// As usual, remove the underscore if you'd like to use the package.
// You may use any packages you'd like.
import (
	"database/sql"
	_ "encoding/json"
	_ "log"
	"net/http"
	_ "strconv"
	_ "time"

	_ "github.com/google/uuid"
	"github.com/gorilla/mux"
)

func RegisterRoutes(router *mux.Router, db *sql.DB) {
	// Spicy regex on the path names to help with integers :^).
	router.HandleFunc("/api/posts/{startIndex:[0-9]+}", getFeed(db)).Methods( /*YOUR CODE HERE*/ )
	router.HandleFunc("/api/posts/{uuid}/{startIndex:[0-9]+}", getPosts(db)).Methods( /*YOUR CODE HERE*/ )
	router.HandleFunc("/api/posts/create", createPost(db)).Methods( /*YOUR CODE HERE*/ )
	router.HandleFunc("/api/posts/delete/{postID}", deletePost(db)).Methods( /*YOUR CODE HERE*/ )
}

// Returns the earliest 25 posts made by the user with ID uuid starting from startIndex.
func getPosts(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// YOUR CODE HERE
	}
}

// Given a JSON containing a field called `postBody` that contains a message (make sure to error check!),
// adds the post to the database with the UUID of the author (which can be found using getUUID),
// a unique ID, and the timestamp of the post.
func createPost(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// YOUR CODE HERE
	}
}

// Given the ID of a post, removes the post from the database if the person requesting
// is the author of the post.
func deletePost(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// YOUR CODE HERE
	}
}

// Similar to getPosts except it gets the posts of everyone else *except* the author.
func getFeed(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// YOUR CODE HERE
	}
}
