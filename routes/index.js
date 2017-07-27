var express = require('express');
var router = express.Router();

/* GET home page. */
router.get('/', function(req, res, next) {
    // res.writeHead(200, {'Content-Type': 'text/html'});
    // res.write('<form action="fileupload" method="post" enctype="multipart/form-data">');
    // res.write('<input type="file" name="filetoupload"><br>');
    // res.write('<input type="submit">');
    // res.write('</form>');
    // return res.end();
  // res.render('main', { title: 'Report Generator Project' });

    res.render('reportMain', { title: "Report Generator Project",
        input_title: "file_path",
        submit_title: "Upload!"});
});

module.exports = router;



