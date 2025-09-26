curl --verbose -b cookies.txt http://127.0.0.1:8081/logout\
  -H "X-CSRF: $(cat csrf.txt)" -H "Content-type: application/json"\
  -d '{"all_devices": false}'
