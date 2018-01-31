// frame busting
function buster(document_in, top_in) {
 if (self === top_in) {
   document_in.documentElement.style.display = "block";
 } else {
   top_in.location = self.location;
 }
}

// html escaping for potentially unsafe jQuery methods such as ".append()"
var entityMap = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#x27;',
    '/': '&#x2F;',
    '`': '&#x60;',
    '=': '&#x3D;'
};

function escapeHtml (string) {
    return String(string).replace(/[&<>"'`=\/]/g, function (s) {
      return entityMap[s];
    });
}