package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gocolly/colly"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	expo "github.com/oliveroneill/exponent-server-sdk-golang/sdk"
	"github.com/robfig/cron/v3"
	_ "github.com/tursodatabase/libsql-client-go/libsql"
	"golang.org/x/crypto/bcrypt"
)

var errUsuarioNaoEncontrado error = errors.New("usuario nao encontrado")
var errSessaoNaoEncontrada error = errors.New("sessao nao encontrada")
var errTokenInvalido error = errors.New("token invalido")
var errTokenExpirado error = errors.New("token expirado")
type resposta struct {
	Success 	bool `json:"success"`
	Data 			any  `json:"data"`
}
type Log struct {
	Status   int  `json:"status"`
	Msg			string `json:"msg"`
	Timestamp  string  `json:"timestamp"`
}

type Manga struct {
	Id    int  `json:"id"`
	Name 	string `json:"name"`
	ChapterNumber  int `json:"chapterNumber"`
	Url    string `json:"url"`
	Image  string `json:"image"`
	LastChapterLink  string `json:"lastChapterLink"`
}

type User struct {
	Id    			int  `json:"id"`
	Username 		string `json:"username"`
	Password  	string `json:"password"`
	Created_at  time.Time `json:"created_at"`
	Updated_at  time.Time `json:"updated_at"`
}

type FavoriteManga struct {
	Id    			int  `json:"id"`
	UserId 		  int `json:"userId"`
	MangaId  	  int `json:"mangaId"`
	Created_at  time.Time `json:"created_at"`
}

type Login struct {
	Id    			int  `json:"id"`
	Username 		string `json:"username"`
	Password  	string `json:"password"`
	Created_at  time.Time `json:"created_at"`
	Updated_at  time.Time `json:"updated_at"`
	TokenNotification string `json:"tokenNotification"`
}
type Session struct {
	Id 					string
	User_id			int 
	Created_at  int64
	Expires_at  int64
	IsActive    int
	TokenNotification string
}

func (s Session) isExpired() bool {
	return s.Expires_at < time.Now().Unix()
}

type UserClaims struct {
	Session_id			string `json:"session_id"`
	jwt.StandardClaims
}
type Image struct {
	Url string  `json:"url"`
}
type Request struct {
	Content string  `json:"content"`
	Embeds []DiscordBody `json:"embeds"`
}
type DiscordBody struct {
	Title       string  `json:"title"`
	Url         string  `json:"url"`
	Type	      string  `json:"type"`
	Description string  `json:"description"`
	Image       Image   `json:"image"`
}

type Database struct {
	con *sql.DB
}

var database *Database

var URL_DISCORD string
var TOKEN string
var CRON_JOB string
var ORIGIN_URL string
var ENVIRONMENT string
const CTX_KEY = "USERID"
func maior(n1 int, n2 int) bool {
	if (n1 >= n2) {
		return false
	} else {
		return true
	}
}

var mangasToSend = []Manga{}

func main() {
	err := godotenv.Load()

	if err != nil {
		erro := fmt.Sprintf("Error carregar .env file: %s", err.Error())
		log.Fatal(erro)
		writeToFile("logs.log", logError(erro))
	}

	TOKEN = os.Getenv("TOKEN")
	URL_DISCORD = os.Getenv("URL_DISCORD")
	DATABASE_URL := os.Getenv("DATABASE_URL_TURSO")
	DATABASE_AUTH := os.Getenv("AUTH_TOKEN_TURSO")
	CRON_JOB := os.Getenv("CRON_JOB")
	ORIGIN_URL := os.Getenv("ORIGIN_URL")
	ENVIRONMENT := os.Getenv("ENVIRONMENT")


	log.Println("ENVIRONMENT", ENVIRONMENT)
	writeToFile("logs.log", logOk(fmt.Sprintf("ENVIRONMENT: %s", ENVIRONMENT)))

	log.Println("ORIGIN_URL", ORIGIN_URL)
	writeToFile("logs.log", logOk(fmt.Sprintf("ORIGIN_URL: %s", ORIGIN_URL)))

	log.Println("CRON_JOB", CRON_JOB)
	writeToFile("logs.log", logOk(fmt.Sprintf("CRON_JOB: %s", CRON_JOB)))

	log.Println("TOKEN DISCORD", TOKEN)
	log.Println("URL_DISCORD", URL_DISCORD)
	writeToFile("logs.log", logOk(fmt.Sprintf("TOKEN DISCORD: %s", TOKEN)))
	writeToFile("logs.log", logOk(fmt.Sprintf("URL_DISCORD: %s", URL_DISCORD)))

	writeToFile("logs.log", logOk(fmt.Sprintf("DATABASE_URL_TURSO: %s", DATABASE_URL)))
	writeToFile("logs.log", logOk(fmt.Sprintf("AUTH_TOKEN_TURSO: %s", DATABASE_AUTH)))
	log.Println("DATABASE URL", DATABASE_URL)
	log.Println("DATABASE AUTH", DATABASE_AUTH)

	url := fmt.Sprintf("%s?authToken=%s", DATABASE_URL, DATABASE_AUTH)

	log.Println("COMPLETE DATABASE URL", url)
	writeToFile("logs.log", logOk(fmt.Sprintf("COMPLETE DATABASE URL: %s", url)))

	db, err := sql.Open("libsql", url)
  if err != nil {
    log.Printf("Erro ao abrir sqlite %s: %s", url, err)
		writeToFile("logs.log", logError(fmt.Sprintf("Erro ao abrir sqlite %s: %s", url, err)))
    os.Exit(1)
  }
  defer db.Close()

	database = &Database{
		con: db,
	}
	cron := cron.New()
	
	id, err := cron.AddFunc(CRON_JOB, start)
	fmt.Println(err)
	cron.Entry(id).Job.Run()
	cron.Start()
	
	router := mux.NewRouter()

	api := router.PathPrefix("/api/").Subrouter()
	api.Use(enableCORS)
	api.HandleFunc("/user", createUser).Methods(http.MethodPost, http.MethodOptions)
	api.HandleFunc("/login", login).Methods(http.MethodPost, http.MethodOptions)
	privateRouter := api.PathPrefix("/").Subrouter()
	privateRouter.Use(AuthMiddleware)
	privateRouter.HandleFunc("/mangas", listMangas).Methods(http.MethodGet, http.MethodOptions)
	privateRouter.HandleFunc("/mangas/me/favorite", createFavoriteManga).Methods(http.MethodPost, http.MethodOptions)
	privateRouter.HandleFunc("/send-notification", sendNotification).Methods(http.MethodPost, http.MethodOptions)


	handler := func (w http.ResponseWriter, r *http.Request) {
		tmpl := template.Must(template.ParseFiles("views/index.html"))
		m, err := queryMangas(database.con)
		if err != nil {
			fmt.Println("QUERY MANGAS - handler", err)
			return
		}
		mangas := map[string][]Manga{
			"Mangas" : m,
		}

		fmt.Println("maa", mangas)
		tmpl.Execute(w, mangas)
	}

	handler2 := func (w http.ResponseWriter, r *http.Request)  {	
		log.Println("HTMX REQUEST RECEIVED")
		log.Println(r.Header.Get("HX-Request"))
		name := r.PostFormValue("manga-name")
		chapter := r.PostFormValue("manga-chapter")
		url := r.PostFormValue("manga-url")
		image := r.PostFormValue("manga-image")
	
		// htmlStr := fmt.Sprintf("<li class='list-group-item'> %s - %s</li>", name, chapter)
		// tmpl, _ := template.New("t").Parse(htmlStr)
		// tmpl.Execute(w, nil)
		chN, _ := strconv.Atoi(chapter)
		m := Manga{
				Name: name,
				ChapterNumber: chN,
				Url: url,
				Image: image,
		}
		_, err := insertManga(database.con, m)

		if err != nil {
			fmt.Println("INSERT MANGA - handler2",err)
			return
		}
		tmpl := template.Must(template.ParseFiles("views/index.html"))
		tmpl.ExecuteTemplate(w, "manga-list-element", m)
	}

	//fs := http.FileServer(http.Dir("views"))
	//http.Handle("/css/", fs) // acessando a pasta css diretamente
	router.HandleFunc("/", handler)
	var add_manga string

	if ENVIRONMENT == "development" {
		// mangazx é a rota no nginx
		add_manga = "/mangazx/add-manga"
	} else {
		add_manga = "/add-manga"
	}

	router.HandleFunc(add_manga,handler2)

	log.Println("Servidor rodando na porta 8080")
	log.Fatal(http.ListenAndServe(":8080", router))
}

func start() {
	simple(database.con)
	//dispatchWebhook()
}

func simple(db *sql.DB) {
	mangas, err := queryMangas(database.con)

	if err != nil {
		erro := fmt.Sprintf("Erro funcao SIMPLE: %s", err.Error())
		log.Fatal(erro)
		writeToFile("logs.log", logError(erro))
		return
	}

	for index, ma := range mangas {
		c := colly.NewCollector()
		
		c.OnError(func(r * colly.Response, e error) {
			erro := fmt.Sprintf("error colly: %s", e.Error())
			log.Fatal(erro)
			writeToFile("logs.log", logError(erro))
		})

		c.OnHTML(".lastend", func(e *colly.HTMLElement) {

			
			// PEGAR O ULTIMO CAPITULO DO MANGA
			lastChapter := e.ChildText("div.inepcx span.epcurlast")

			lastChapterLink := e.ChildAttr(".inepcx:nth-of-type(2) a", "href")

			lastChapterNumber := strings.Split(lastChapter, " ")[1]
			n, err := strconv.Atoi(lastChapterNumber)

			if err != nil {
				erro := fmt.Sprintln("Erro ao converter numero do capitulo para tipo number")
				log.Fatal(erro)
				writeToFile("logs.log", logError(erro))
			}

			if (maior(mangas[index].ChapterNumber, n)) {
				mangas[index].ChapterNumber = n
				mangasToSend = append(mangasToSend,mangas[index])
				updateManga(db, mangas[index].Id, n, lastChapterLink)
			}
		})
		
		c.Visit(ma.Url)
	}
}

func dispatchWebhook() {
	if (len(mangasToSend) == 0) {
		ok := fmt.Sprintln("Nada enviado")
		log.Println(ok)
		writeToFile("logs.log", logOk(ok))
		return
	}
	var jsonBody = DiscordBody{}
	var embedAr = []DiscordBody{}

	for _, ch := range mangasToSend {
		jsonBody.Description = fmt.Sprintf("capitulo %d", ch.ChapterNumber)
		jsonBody.Image.Url = ch.Image
		jsonBody.Title = ch.Name
		jsonBody.Url = ch.Url
		jsonBody.Type = "rich"

		embedAr = append(embedAr, jsonBody)
	}
	
	j := Request{
		Content: "ATUALIZACOES",
    Embeds: embedAr,
	}

	jsonData, err := json.Marshal(j)

	if err != nil {
		erro := fmt.Sprintf("Error json Marshal: %s", err.Error())
		log.Fatal(erro)
		writeToFile("logs.log", logError(erro))
		return
	}

	payload := bytes.NewBuffer(jsonData)

	r, err := http.NewRequest("POST", URL_DISCORD, payload)

	mangasToSend = nil

	if err != nil {
		erro := fmt.Sprintf("Erro new Request: %s", err.Error())
		log.Fatal(erro)
		writeToFile("logs.log", logError(erro))
		panic(err)
	}

	r.Header.Add("Content-Type", "application/json")
	r.Header.Add("Authorization", fmt.Sprintf("Bot %s", TOKEN))
	
	log.Println("payload",payload)
	writeToFile("logs.log", logOk(payload.String()))

	client := &http.Client{}

	res, err := client.Do(r)

	if err != nil {
		erro := fmt.Sprintf("Erro Client Do: %s", err.Error())
		log.Fatal(erro)
		writeToFile("logs.log", logError(erro))
		panic(err)
	}

	defer res.Body.Close()
}

func sendNotificationToDevices() {

}

func sendNotification(w http.ResponseWriter, r *http.Request) {
	// To check the token is valid
	pushToken, err := expo.NewExponentPushToken("")
	if err != nil {
			panic(err)
	}

	// Create a new Expo SDK client
	client := expo.NewPushClient(nil)

	// Publish message
	response, err := client.Publish(
			&expo.PushMessage{
					To: []expo.ExponentPushToken{pushToken},
					Body: "This is a test notification",
					Data: map[string]string{"withSome": "data"},
					Sound: "default",
					Title: "Notification Title",
					Priority: expo.DefaultPriority,
			},
	)
	
	// Check errors
	if err != nil {
			panic(err)
	}
	
	// Validate responses
	if response.ValidateResponse() != nil {
			fmt.Println(response.PushMessage.To, "failed")
	}
	toJSON(w, 200, "ok")
}

func listMangas(w http.ResponseWriter, r *http.Request) {
	mangas, err := queryMangas(database.con)

	if err != nil {
		erro := fmt.Sprintf("erro ao listar manga: %s", err.Error())
		log.Panic(erro)
		writeToFile("logs.log", logError(erro))
		return
	}

  toJSON(w, http.StatusOK, mangas)
}

func createFavoriteManga(w http.ResponseWriter, r *http.Request) {
	var fav FavoriteManga 
	json.NewDecoder(r.Body).Decode(&fav)

	ctx := r.Context()

	userId := getUserId(ctx)
	
	userIdInt, err := strconv.Atoi(userId)

	if err != nil {
		fmt.Println("erro de conversao", err)
	}
	 _, errr := insertFavoriteManga(database.con, FavoriteManga{
		UserId: userIdInt,
		MangaId: fav.MangaId,
	})

	if errr != nil {
		writeToFile("logs.log", logError(err.Error()))
		toJSON(w, http.StatusInternalServerError, "erro ao inserir manga favorito")
		return
	}

	d := struct {
		Message 					string 	`json:"message"`
	} {
		Message: "ok",
	}

	toJSON(w, http.StatusOK, d)
}
func createUser(w http.ResponseWriter, r *http.Request) {
	var user User 
	json.NewDecoder(r.Body).Decode(&user)
	w.Header().Set("Content-type", "application/json")

	p, err := HashPassword(user.Password)
	
	if err != nil {
		erro := fmt.Sprintf("erro ao criptografar senha: %s", err.Error())
		log.Panic(erro)
		writeToFile("logs.log", logError(erro))
		return
	}

	user.Password = p

	_, err = insertUser(database.con, user)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		res := resposta {
			Success: false,
			Data: "Erro	ao criar usuario",
		}
		jsonValue, _ := json.Marshal(res)
		w.Write(jsonValue)
		return
	}

	d := struct {
		Username 					string 	`json:"username"`
	} {
		Username: user.Username,
	}

	res := resposta {
		Success: true,
		Data: d,
	}

	jsonValue, _ := json.Marshal(res)
	w.WriteHeader(http.StatusCreated)
	w.Write(jsonValue)
}

func login(w http.ResponseWriter, r *http.Request) {
	var user Login 
	json.NewDecoder(r.Body).Decode(&user)

	userDb, err := findUserByUsername(database.con, user.Username)

	if err == errUsuarioNaoEncontrado {
		erro := fmt.Sprintf("%s", err)
		writeToFile("logs.log", logError(erro))
		toJSON(w, http.StatusUnprocessableEntity, "usuario ou senha invalidos")
		return
	}

	isValidPassword := CheckPasswordHash(user.Password, userDb.Password)
	
	if !isValidPassword {
		writeToFile("logs.log", logError("Senha invalida"))
		toJSON(w, http.StatusUnprocessableEntity, "usuario ou senha invalidos")
		return
	}

	sessionToken := uuid.NewString()
	currentTime := time.Now()
	expiresAt := currentTime.Add(744 * time.Hour).Unix()
	
	insertSession(database.con, Session{
		Id: sessionToken,
		User_id: userDb.Id,
		Created_at: currentTime.Unix(),
		Expires_at: expiresAt,
		TokenNotification: user.TokenNotification,
	})

	userClaims := UserClaims{
		Session_id: sessionToken,
		StandardClaims: jwt.StandardClaims{
			IssuedAt: currentTime.Unix(),
			ExpiresAt: expiresAt,
		},
	}
	accessToken, err := NewAccessToken(userClaims)

	if err != nil {
		fmt.Println("Erro ao gerar novo token de login", err)
	}

	d := struct {
		Access_token 					string 	`json:"access_token"`
	} {
		Access_token: accessToken,
	}

	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	
	toJSON(w, http.StatusOK, d)
}

func toJSON(w http.ResponseWriter, statusCode int, msg any) {
	w.Header().Set("Content-type", "application/json")
	var res resposta
	if statusCode == 200 || statusCode == 201 {
		res = resposta {
			Success: true,
			Data: msg,
		}
	} else {
		res = resposta {
			Success: false,
			Data: msg,
		}
	}
	
	w.WriteHeader(statusCode)
	jsonValue, _ := json.Marshal(res)
	w.Write(jsonValue)
}

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func (w http.ResponseWriter, r *http.Request) {
		authorization := r.Header.Get("Authorization")
		if authorization == "" {
			log.Println("nao token")
			toJSON(w, http.StatusUnauthorized, "token invalido")
			return 
		}

		token := strings.Split(authorization, " ")[1]

		tokenSession, errToken := ParseAccessToken(token)

		if errors.Is(errToken, errTokenInvalido) {
			fmt.Println("AUTENTICAÇÃO MIDDLEWARE TOKEN INVALIDO", errToken.Error())
			toJSON(w, http.StatusUnauthorized, errTokenInvalido.Error())
			return
		}

		if errors.Is(errToken, errTokenExpirado) {
			fmt.Println("AUTENTICAÇÃO MIDDLEWARE TOKEN EXPIRADO", errToken.Error())
			toJSON(w, http.StatusUnauthorized, errTokenExpirado.Error())
			return
		}

		session, err := findSessionById(database.con, tokenSession.Session_id, 1)

		if err == errSessaoNaoEncontrada {
			erro := fmt.Sprintf("%s", err)
			writeToFile("logs.log", logError(erro))
			toJSON(w, http.StatusUnauthorized, "sessao nao encontrada")
			return
		}
		
		if session.isExpired() {
			log.Println("expirado")
			deleteSession(database.con, tokenSession.Session_id)
			toJSON(w, http.StatusUnauthorized, "nao autorizado")
			return
		}
		
		ctx := r.Context()
	
		ctx = context.WithValue(ctx, CTX_KEY,strconv.Itoa(session.User_id))

		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

func getUserId(ctx context.Context) string {
	userId := ctx.Value(CTX_KEY)

	reqID, ok := userId.(string)
	if !ok {
		fmt.Println("error", ok)
	}
	return reqID
}
func enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//log.Println("CORS", ORIGIN_URL)
		if (ENVIRONMENT == "production") {
			w.Header().Set("Access-Control-Allow-Origin", ORIGIN_URL)
		} else {
			w.Header().Set("Access-Control-Allow-Origin", "http://localhost:8081")
		}

		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT")

		if r.Method == "OPTIONS" {
			w.WriteHeader(204)
			return
	}

		next.ServeHTTP(w, r)
	})	
}
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	return string(bytes), err
}

func CheckPasswordHash(password, passwordHashed string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(passwordHashed), []byte(password))
	return err == nil
}

func insertFavoriteManga(db *sql.DB, favManga FavoriteManga) (int64, error) {
	slqStatementUpdt := `INSERT INTO favorites_mangas
	(user_id, manga_id) VALUES (?, ?)`

	fmt.Println("fav", favManga)
	result, err := db.Exec(slqStatementUpdt, 
		favManga.UserId,
		favManga.MangaId,
	)

	if err != nil {
		erro := fmt.Sprintf("Erro ao rodar INSERT FAVORITE MANGA: %s", err.Error())
    log.Panic(erro)
		writeToFile("logs.log", logError(erro))
		return 0, err
	}

	rowsAffected, err := result.RowsAffected()

	if err !=  nil {
		erro := fmt.Sprintf("Erro ao retornar linhas afetadas INSERT FAVORITE MANGA: %s", err.Error())
    log.Panic(erro)
		writeToFile("logs.log", logError(erro))
		return 0, err
	}
	
	ok := fmt.Sprintf("Inserindo favorite manga: %v", favManga)
	log.Printf("%s",ok)
	writeToFile("logs.log", logOk(ok))
	return rowsAffected, nil
}

func insertSession(db *sql.DB, session Session) (int64, error) {
	slqStatementUpdt := `INSERT INTO sessions 
	(id, user_id, created_at, expires_at, isActive, tokenNotification) VALUES (?, ?, ?, ?, ?, ?)`

	result, err := db.Exec(slqStatementUpdt, 
		session.Id,
		session.User_id,
		session.Created_at,
		session.Expires_at,
		1,
		session.TokenNotification,
	)

	if err != nil {
		erro := fmt.Sprintf("Erro ao rodar INSERT SESSION: %s", err.Error())
    log.Panic(erro)
		writeToFile("logs.log", logError(erro))
		return 0, err
	}

	rowsAffected, err := result.RowsAffected()

	if err !=  nil {
		erro := fmt.Sprintf("Erro ao retornar linhas afetadas INSERT SESSION: %s", err.Error())
    log.Panic(erro)
		writeToFile("logs.log", logError(erro))
		return 0, err
	}
	
	ok := fmt.Sprintf("Inserindo session: %v", session)
	log.Printf(ok)
	writeToFile("logs.log", logOk(ok))
	return rowsAffected, nil
}

func deleteSession(db *sql.DB, id string) (int64, error) {
	slqStatementUpdt := `UPDATE sessions SET isActive = 0 WHERE id = ?`

	result, err := db.Exec(slqStatementUpdt, 
		id,
	)

	if err != nil {
		erro := fmt.Sprintf("Erro ao rodar DELETE SESSION: %s", err.Error())
    log.Panic(erro)
		writeToFile("logs.log", logError(erro))
		return 0, err
	}

	rowsAffected, err := result.RowsAffected()

	if err !=  nil {
		erro := fmt.Sprintf("Erro ao retornar linhas afetadas DELETE SESSION: %s", err.Error())
    log.Panic(erro)
		writeToFile("logs.log", logError(erro))
		return 0, err
	}
	
	ok := fmt.Sprintf("deletando session: %v", id)
	log.Printf(ok)
	writeToFile("logs.log", logOk(ok))
	return rowsAffected, nil
}

func queryMangas (db *sql.DB) ([]Manga, error) {
	rows, err := db.Query("SELECT * FROM mangas")
  if err != nil {
		erro := fmt.Sprintf("Erro ao executar query QUERY MANGAS: %s", err.Error())
    log.Panic(erro)
		writeToFile("logs.log", logError(erro))
    os.Exit(1)
  }
  defer rows.Close()

	var mangas []Manga

  for rows.Next() {
    var manga Manga

    if err := rows.Scan(&manga.Id, &manga.Name, &manga.ChapterNumber, &manga.Url, &manga.Image, &manga.LastChapterLink); err != nil {
			erro := fmt.Sprintf("Erro ao escanear linha QUERY MANGAS: %s", err.Error())
			log.Panic(erro)
			writeToFile("logs.log", logError(erro))
      return nil, err
    }

    mangas = append(mangas, manga)
  }

  if err := rows.Err(); err != nil {
		erro := fmt.Sprintf("Erro ao iterar pelas linhas QUERY MANGAS: %s", err.Error())
		log.Panic(erro)
		writeToFile("logs.log", logError(erro))
		return nil, err
  }

	return mangas, nil
}

func insertManga(db *sql.DB, manga Manga) (int64, error) {
	slqStatementUpdt := `INSERT INTO mangas 
	(name, chapterNumber, url, image) VALUES (?, ?, ?, ?)`

	result, err := db.Exec(slqStatementUpdt, 
		manga.Name, 
		manga.ChapterNumber,
		manga.Url,
		manga.Image,
	)

	if err != nil {
		erro := fmt.Sprintf("Erro ao rodar INSERT MANGA: %s", err.Error())
    log.Panic(erro)
		writeToFile("logs.log", logError(erro))
		return 0, err
	}

	rowsAffected, err := result.RowsAffected()

	if err !=  nil {
		erro := fmt.Sprintf("Erro ao retornar linhas afetadas INSERT MANGA: %s", err.Error())
    log.Panic(erro)
		writeToFile("logs.log", logError(erro))
		return 0, err
	}
	
	ok := fmt.Sprintf("Inserindo manga: %v", manga)
	log.Printf(ok)
	writeToFile("logs.log", logOk(ok))
	return rowsAffected, nil
}

func updateManga(db *sql.DB, id int, chapterNumber int, lastChapterLink string) (int64, error) {
	slqStatementUpdt := `UPDATE mangas SET chapterNumber = ?, lastChapterLink = ? WHERE id = ?`

	result, err := db.Exec(slqStatementUpdt, chapterNumber, lastChapterLink, id)

	if err != nil {
		erro := fmt.Sprintf("Erro ao rodar UPDATE MANGA: %s", err.Error())
    log.Panic(erro)
		writeToFile("logs.log", logError(erro))
		return 0, err
	}

	rowsAffected, err := result.RowsAffected()

	if err !=  nil {
		erro := fmt.Sprintf("Erro ao retornar linhas afetadas UPDATE MANGA: %s", err.Error())
    log.Panic(erro)
		writeToFile("logs.log", logError(erro))
		return 0, err
	}
	
	ok := fmt.Sprintf("Atualizado manga id %d capitulo %d", id, chapterNumber)
	log.Printf("Atualizado manga id %d capitulo %d", id, chapterNumber)
	logOk(ok)

	return rowsAffected, nil
}

func insertUser(db *sql.DB, user User) (int64, error) {
	slqStatementUpdt := `INSERT INTO users 
	(username, password) VALUES (?, ?)`

	result, err := db.Exec(slqStatementUpdt, 
		user.Username, 
		user.Password,
	)

	if err != nil {
		erro := fmt.Sprintf("Erro ao rodar INSERT USER: %s", err.Error())
    log.Panic(erro)
		writeToFile("logs.log", logError(erro))
		return 0, err
	}

	rowsAffected, err := result.RowsAffected()

	if err !=  nil {
		erro := fmt.Sprintf("Erro ao retornar linhas afetadas INSERT USER: %s", err.Error())
    log.Panic(erro)
		writeToFile("logs.log", logError(erro))
		return 0, err
	}
	
	ok := fmt.Sprintf("Inserindo user: %v", user)
	log.Printf(ok)
	writeToFile("logs.log", logOk(ok))
	return rowsAffected, nil
}

func findUserByUsername (db *sql.DB, username string) (User, error) {
	sqlStatement := "SELECT id, username, password FROM users WHERE username = ?"
	var user User
	row := db.QueryRow(sqlStatement, username)
	
	err := row.Scan(&user.Id, &user.Username, &user.Password)

	switch err {
	case sql.ErrNoRows: 
	return User{}, errUsuarioNaoEncontrado
	case nil:
		return user, nil
	default:
		erro := fmt.Sprintf("Erro ao encontrar usuario por nome: %s", err.Error())
    log.Panic(erro)
		writeToFile("logs.log", logError(erro))
		panic(err)
	}
}

func findSessionById (db *sql.DB, id string, isActive int) (Session, error) {
	var sqlStatement string
	if isActive == 1 {
		sqlStatement = "SELECT id, user_id, created_at, expires_at FROM sessions WHERE id = ? AND isActive = 1"
	} else if isActive == 0 {
		sqlStatement = "SELECT id, user_id, created_at, expires_at FROM sessions WHERE id = ? AND isActive = 0"
	} else {
		sqlStatement = "SELECT id, user_id, created_at, expires_at FROM sessions WHERE id = ?"
	}
	log.Println(sqlStatement)
	var session Session
	row := db.QueryRow(sqlStatement, id)
	
	err := row.Scan(&session.Id, &session.User_id, &session.Created_at, &session.Expires_at)

	switch err {
	case sql.ErrNoRows: 
	log.Println("no rows")
	return Session{}, errSessaoNaoEncontrada
	case nil:
		return session, nil
	default:
		erro := fmt.Sprintf("Erro ao encontrar sessao por id: %s", err.Error())
    log.Panic(erro)
		writeToFile("logs.log", logError(erro))
		panic(err)
	}
}

func writeToFile (pathWithFileName string, text string) error {
	file, err := os.OpenFile(pathWithFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	if err != nil {
		fmt.Printf("Erro ao CRIAR arquivo %s o texto: %s", pathWithFileName, text)
		return err
	}
	defer file.Close()

	if _, err := file.WriteString(fmt.Sprintf("%s\n", text)); err != nil {
		log.Printf("Erro ao ESCREVER arquivo %s o text: %s", pathWithFileName, text)
	}

	return file.Close()
}

func logOk(msg string) string {
	log := Log {
		 Status: 200,
		 Timestamp: time.Now().Format("2006-01-02 15:04:05"),
		 Msg: msg,
	}

	j, err := json.Marshal(log)

	if err != nil {
		fmt.Println("Erro ao converter log ok")
		panic(err)
	}
	txt := string(j)
	return txt
}

func logError(msg string) string {
	log := Log {
		Status: 500,
		Timestamp: time.Now().Format("2006-01-02 15:04:05"),
		Msg: msg,
	}

	j, err := json.Marshal(log)

	if err != nil {
		fmt.Println("Erro ao converter log ok")
		panic(err)
	}
	txt := string(j) 
	return txt
}

func NewAccessToken(claims UserClaims) (string, error) {
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return accessToken.SignedString([]byte("SECRET_TOKEN"))
}

func ParseAccessToken(accessToken string) (*UserClaims, error) {
	parsedAccessToken, _ := jwt.ParseWithClaims(
		accessToken,
		&UserClaims{},
		func(t *jwt.Token) (interface{}, error) {
			return []byte("SECRET_TOKEN"), nil
		},
	)

	claims, ok := parsedAccessToken.Claims.(*UserClaims)

	if !ok {
		return nil, errTokenInvalido
	}

	if claims.ExpiresAt < time.Now().Unix() {
		return nil, errTokenExpirado
	}

	return claims, nil
}

