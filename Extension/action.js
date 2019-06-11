

function copiarPortapapeles() {
  var copyText = document.getElementById("password");

  copyText.select();

  document.execCommand("copy");

}

function autocompletar(nick, pass){
    document.getElementById("email").value = nick;
    document.getElementById("pass").value = pass;
}
function load() {
  document.getElementById("user").style.visibility = 'hidden'
  document.getElementById("password").style.visibility = 'hidden'

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
                //  console.log(xhr.responseText)
                  if(json.ok == true){

                    chrome.tabs.query({'active': true, 'windowId': chrome.windows.WINDOW_ID_CURRENT}, function (tabs) {
                        var url = tabs[0].url + '';   
                       console.log(url)
                        json.data.forEach(pass => {
                            console.log(pass.Url)
                            if(url.includes(pass.Url.split(".",2)[0])){
                              document.getElementById("msg").innerText = "Tienes una cuenta en este sitio"
                              document.getElementById("user").style.visibility = 'visible'
                              document.getElementById("password").style.visibility = 'visible'
                              document.getElementById("user").value = pass.Nick
                              document.getElementById("password").value = pass.Pass
                            }
                        });
                    });
                    
                  }else{
                    document.getElementById("msg").innerText = "No tienes una cuenta en este sitio"
                  }
              } else {
                console.log("ERROR", xhr)
              }
          };
          xhr.send(formBody);

    })
}

window.onload = load;


