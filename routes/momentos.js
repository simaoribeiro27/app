var express = require('express');
var router = express.Router();
var mongojs = require('mongojs');
// the db is on a remote server (the port default to mongo) 
var db = mongojs('mongodb://alfa:alfa1963@ds159880.mlab.com:59880/bdviagens', ['momentos']);



//multer object creation
var multer = require('multer');
var storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, './public/uploads')
    },
    filename: function (req, file, cb) {
        cb(null, file.originalname)
    }
})
var upload = multer({ storage: storage })


var momento = {
    Localidade: { type: String, required: true },
    Tempo: String,
    Localizacao: { coordinates: [,] },
    Descricao: String,
    ImagemUrl: { type: String, required: true },
    Visivel: { type: Boolean, default: false },
    Data: { type: Date },
    idViagem: String,
};

/* GET ALL     /momentos */
router.get('/momentos', function (req, res, next) {
    db.momentos.find(function (err, momentos) {
        if (err) { res.send(err); }
        console.log('Todas as momentos: ' + JSON.stringify(momentos));
        res.json(momentos);
    });
});

/* GET ONE   /momentos/id */
router.get('/momentos/:id', function (req, res, next) {
    db.momentos.findOne({ _id: mongojs.ObjectId(req.params.id) }, function (err, momento) {
        if (err) { res.send(err); }
        console.log('momento id: ' + JSON.stringify(momento));
        res.json(momento);
    });
});


/* DELETE    /momentos/id */
router.delete('/momentos/:id', function (req, res, next) {
    db.momentos.remove({ _id: mongojs.ObjectId(req.params.id) }, function (err, momento) {
        if (err) { res.send(err); }
        console.log('momento retirado: ' + JSON.stringify(momento));
        res.json(momento);
    });
});

/* POST /momentos */
router.post('/momentos', upload.single('Media'), function (req, res) {
    momento = req.body;
    momento.ImagemUrl = req.file.path;
    //Media=carrega imagem
    db.momentos.insert(momento, function (err, momento) {
        if (err) {
            res.send({ 'erro': 'Ocorreu um erro' });
        } else {
            console.log('momento inserido: ' + JSON.stringify(momento));
            res.send(momento);
        }
    });
});

/* PUT     /momentos/id */
router.put('/momentos/:id', function (req, res) {
    var Descricao = req.body.Descricao;
    console.log(JSON.stringify(momento));
    db.momentos.update({ _id: mongojs.ObjectId(req.params.id) }, { $set: { Descricao } }, function (err, resultado) {
        if (err) {
            res.send({ 'erro': 'Ocorreu um erro' });
        } else {
            console.log('' + resultado + 'momento alterado');
            res.send(momento);
        }
    });
});


module.exports = router;