package withstandleaderboard

import (
	"crypto/sha512"
	"net/http"
	"strconv"

	"google.golang.org/appengine"
	"google.golang.org/appengine/datastore"

	"encoding/base64"

	"strings"

	"github.com/gorilla/mux"
)

func init() {
	r := mux.NewRouter()

	r.HandleFunc("/scores/{name}/{password}/{score}", postScoreHandler).
		Methods("POST")
	r.HandleFunc("/scores", getScoresHandler).
		Methods("GET")

	http.Handle("/", r)
}

type Player struct {
	Name     string `json:"name"`
	Score    int    `json:"score"`
	Password string `json:"-"`
}

func postScoreHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ctx := appengine.NewContext(r)

	nameData, err := base64.RawURLEncoding.DecodeString(vars["name"])
	if err != nil {
		responseError(w, "Invalid name", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(string(nameData))

	if len(name) < 4 || len(name) > 12 {
		responseError(w, "Invalid name", http.StatusBadRequest)
		return
	}

	passwordData, err := base64.RawURLEncoding.DecodeString(vars["password"])
	if err != nil {
		responseError(w, "Invalid password", http.StatusBadRequest)
		return
	}
	password := strings.TrimSpace(string(passwordData))
	if len(password) < 4 || len(password) > 32 {
		responseError(w, "Invalid password", http.StatusBadRequest)
		return
	}

	hasher := sha512.New()
	hasher.Write([]byte(password))
	passwordHash := base64.URLEncoding.EncodeToString(hasher.Sum(nil))

	score, err := strconv.ParseInt(vars["score"], 10, 32)
	if err != nil {
		responseError(w, "Invalid score", http.StatusBadRequest)
		return
	}

	player := &Player{}
	key := datastore.NewKey(ctx, "Player", name, 0, nil)

	if err = datastore.Get(ctx, key, player); err != nil {
		player.Name = name
		player.Password = passwordHash
		player.Score = 0
	}

	if player.Password != passwordHash {
		responseError(w, "Incorrect password", http.StatusUnauthorized)
		return
	}

	if int(score) > player.Score {
		player.Score = int(score)
		_, err = datastore.Put(ctx, key, player)

		if err != nil {
			responseError(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	responseJSON(w, nil)
}

type GetScoresResult struct {
	Players []Player `json:"players"`
}

func getScoresHandler(w http.ResponseWriter, r *http.Request) {
	ctx := appengine.NewContext(r)

	var players []Player
	if _, err := datastore.NewQuery("Player").Order("-Score").GetAll(ctx, &players); err != nil {
		responseError(w, err.Error(), http.StatusInternalServerError)
	} else {
		responseJSON(w, GetScoresResult{players})
	}
}
