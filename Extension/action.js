
String.prototype.hashCode = function () {
    if (Array.prototype.reduce) {
        return this.split("").reduce(function (a, b) { a = ((a << 5) - a) + b.charCodeAt(0); return a & a }, 0);
    }
    var hash = 0;
    if (this.length === 0) return hash;
    for (var i = 0; i < this.length; i++) {
        var character = this.charCodeAt(i);
        hash = ((hash << 5) - hash) + character;
        hash = hash & hash; // Convert to 32bit integer
    }
    return hash;
}

function load() {
    document.querySelector("button").addEventListener("click", function () {

        var nick = document.getElementById("nick").value
        var pass = document.getElementById("pass").value


        var details = {
            'name': nick,
            'pass': pass
          };
  
          var formBody = [];
          for (var property in details) {
            var encodedKey = encodeURIComponent(property);
            var encodedValue = encodeURIComponent(details[property]);
            formBody.push(encodedKey + "=" + encodedValue);
          }
          formBody = formBody.join("&");
  
          var xhr = new XMLHttpRequest();
          xhr.open('POST', 'https://127.0.0.1:443/loginExtension', false); //false así funciona
          // xhr.timeout = 10000; // only for asynchronous
          xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
          xhr.onreadystatechange = function() {
              if (xhr.readyState === 4 || xhr.readyState === XMLHttpRequest.DONE) {
                  //console.log(xhr.responseText)
                  var json = JSON.parse(xhr.responseText)
                 

                  if(json.ok == true){

                    chrome.tabs.query({'active': true, 'windowId': chrome.windows.WINDOW_ID_CURRENT}, function (tabs) {
                        var url = tabs[0].url + '';   
                       console.log(url)
                        json.data.forEach(pass => {
                            console.log(pass.Url)
                            if(url.includes(pass.Url.split(".",2)[0])){
                                alert('tienes una contraseña de este sitio')
                            }else{
                                console.log("Ninguna contraseña es de esta web")
                            }
                        });
                    });
                    
                  }else{

                  }
              } else {
                console.log("ERROR", xhr)
              }
          };
          xhr.send(formBody);

    })
}

window.onload = load;


