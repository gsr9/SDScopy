
const copyToClipBoard = (str) =>
{
    const el = document.createElement('textarea');
    el.value = str;
    document.body.appendChild(el);
    el.select();
    document.execCommand('copy');
    document.body.removeChild(el);
};
function copiarPortapapeles() {
  var copyText = document.getElementById("password").value;


  chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
    console.log("TAB ", tabs);
    chrome.tabs.sendMessage(tabs[0].id, {user : "gsr@alu.ua.es", pass : "gsr"}, function(response) {
                                   console.log("hola", response);
      });
 });


  copyToClipBoard(copyText)

}

function autocompletar(nick, pass){
    document.getElementById("email").value = nick;
    document.getElementById("pass").value = pass;
}
function load() {
  
  document.getElementById("user").style.visibility = 'hidden'
  document.getElementById("password").style.visibility = 'hidden'
  document.getElementById("btnCopy").style.visibility = 'hidden'

  if(parseCookie('name') !== '' && parseCookie('pass') !== ''){
    document.querySelector('.form').innerHTML = ''
    getPasswords(parseCookie('name'), parseCookie('pass'))
} else{
  document.getElementById("btnLogin").addEventListener("click", function () {

      var nick = document.getElementById("nick").value
      var pass = document.getElementById("pass").value

      getPasswords(nick, pass)

  })
}

  document.getElementById("btnCopy").addEventListener("click",copiarPortapapeles)
}

function getPasswords(nick, pass) {
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
              document.querySelector('.form').innerHTML = ''
              chrome.tabs.query({'active': true, 'windowId': chrome.windows.WINDOW_ID_CURRENT}, function (tabs) {
                  var url = tabs[0].url + '';
                  console.log(url)
                  json.data.forEach(pass => {
                      console.log(pass.Url)
                      var date = new Date();
                      date.setDate(date.getDate() + 1);
                      document.cookie = "sdsToken=; expires="+new Date()+"; path=/"
                      document.cookie = "name="+nick+"; expires="+date.toString()+"; path=/"
                      document.cookie = "pass="+details['pass']+"; expires="+date.toString()+"; path=/"
                      if(url.includes(pass.Url.split(".",2)[0])){
                        document.getElementById("msg").innerText = "Tienes una cuenta en este sitio"
                        document.getElementById("user").style.visibility = 'visible'
                        document.getElementById("password").style.visibility = 'visible'
                        document.getElementById("user").value = pass.Nick
                        document.getElementById("password").value = pass.Pass

                        document.getElementById("btnCopy").style.visibility = 'visible'
                      } else{
                        document.getElementById("msg").innerText = "No tienes una cuenta en este sitio"
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
}

function parseCookie(cookieName) {
  var cookies = document.cookie.split(';')
  for (cookie of cookies) {
    var aux = cookie.split('=')
    if(aux[0].replace(/\s/g, '') === cookieName){
      return aux[1]
    }
  }
  return ''
}

window.onload = load;
