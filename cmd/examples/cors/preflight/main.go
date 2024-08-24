package main

import (
	"flag"
	"log"
	"net/http"
)

const html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Simple CORS</title>
</head>
<body>
    <h1>Simple CORS</h1>
    <div id="output"></div>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            fetch("http://localhost:4000/v1/tokens/authentication", {
                method: "POST",
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    email: 'alice@example.com',
                    password: 'pa55word'
                })
            }).then(function(response) {
                if (response.ok) {
                    return response.text();
                } else {
                    throw new Error('Network response was not ok');
                }
            }).then(function(text) {
                document.getElementById("output").innerHTML = text;
            }).catch(function(error) {
                document.getElementById("output").innerHTML = error.message;
            });
        });
    </script>
</body>
</html>
`

func main() {
	addr := flag.String("addr", ":9000", "listen address")
	flag.Parse()

	log.Printf("listening on %s", *addr)
	err := http.ListenAndServe(*addr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(html))
	}))
	log.Fatal(err)
}
