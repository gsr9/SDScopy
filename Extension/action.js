
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

        var p = "H0D8ktokFpR1CXnubPWC8tXX0o4YM13gWrxU0FYOD1M="

        var form = {
            name: nick,
            pass: pass
        }

        fetch("https://localhost:443/loginExtension",
        {
            headers: {
                "Content-Type":"application/json"
            },
            method: "POST",
            body: JSON.stringify(form)
        })
        .then(function(res){ 
            console.log(res)
            return res.json()
        })
        .then(function(data){ alert( JSON.stringify( data ) ) })    

    })
}

window.onload = load;


