package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gocolly/colly"
	"github.com/joho/godotenv"
	"github.com/robfig/cron/v3"
	_ "github.com/tursodatabase/libsql-client-go/libsql"
)

type Log struct {
	Status   int  `json:"status"`
	Msg			string `json:"msg"`
	Timestamp  string  `json:"timestamp"`
}

type Manga struct {
	id    int  
	name 	string;
	chapterNumber  int;
	url    string;
	image  string;
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

	http.ListenAndServe(":8080", nil)
}

func start() {
	simple(database.con)
	dispatchWebhook()
}

func simple(db *sql.DB) {
	mangas, err := queryMangas(db)

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

			lastChapterNumber := strings.Split(lastChapter, " ")[1]
			n, err := strconv.Atoi(lastChapterNumber)

			if err != nil {
				erro := fmt.Sprintln("Erro ao converter numero do capitulo para tipo number")
				log.Fatal(erro)
				writeToFile("logs.log", logError(erro))
			}

			if (maior(mangas[index].chapterNumber, n)) {
				mangas[index].chapterNumber = n
				mangasToSend = append(mangasToSend,mangas[index])
				updateManga(db, mangas[index].id, n)
			}
		})
		
		c.Visit(ma.url)
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
		jsonBody.Description = fmt.Sprintf("capitulo %d", ch.chapterNumber)
		jsonBody.Image.Url = ch.image
		jsonBody.Title = ch.name
		jsonBody.Url = ch.url
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

    if err := rows.Scan(&manga.id, &manga.name, &manga.chapterNumber, &manga.url, &manga.image); err != nil {
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

func updateManga(db *sql.DB, id int, chapterNumber int) (int64, error) {
	slqStatementUpdt := `UPDATE mangas SET chapterNumber = ? WHERE id = ?`

	result, err := db.Exec(slqStatementUpdt, chapterNumber, id)

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