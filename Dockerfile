FROM golang:1.21.2-alpine3.18 AS BUILD

WORKDIR /app

COPY . .

RUN go build -o web-scrapping

###DEPLOY

FROM alpine:latest

WORKDIR /app 
COPY --from=BUILD /app/web-scrapping /app
COPY --from=BUILD /app/views /app/views

EXPOSE 8080

CMD [ "./web-scrapping" ]