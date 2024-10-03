
function autologin(url, callback, timeout) {
  function createCookie(name,value,seconds) {
      if (seconds) {
            var date = new Date();
                date.setTime(date.getTime() + (seconds*1000));
                    var expires = "; expires="+date.toGMTString();
                      }
        else var expires = "";
          document.cookie = name+"="+value+expires+"; path=/";
  }

  function readCookie(name) {
      var nameEQ = name + "=";
        var ca = document.cookie.split(';');
          for(var i=0;i < ca.length;i++) {
                var c = ca[i];
                    while (c.charAt(0)==' ') c = c.substring(1,c.length);
                        if (c.indexOf(nameEQ) == 0) return c.substring(nameEQ.length,c.length);
                      }
            return null;
  }
  function getXmlHttpRequestObject() {
      if(window.ActiveXObject) {
          return new ActiveXObject("Microsoft.XMLHTTP"); //IE
      } else {
          return new XMLHttpRequest(); 
      }
  }
  timeout = timeout || (60*15);
  if (readCookie('autologin')) {
    callback(false);
  } else {
    xhr = getXmlHttpRequestObject();
    xhr.open("GET", url, true);
    xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
    xhr.onreadystatechange = function () {
      if (xhr.readyState == 4) {
        var ok = xhr.responseText == 'true';
        callback(ok);
        if (ok) {
          createCookie('autologin', '1', timeout);
        }
      }
    }
    xhr.send(null);
  }
}
