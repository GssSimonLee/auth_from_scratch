curl -i -c cookies.txt http://127.0.0.1:8081/login\
  -H "Content-Type: application/json"\
  -d '{ "username": "simon", "password": "Passw0rd!" }'

