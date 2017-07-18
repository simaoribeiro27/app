var express = require('express');
var router = express.Router();
var mongojs = require('mongojs');
var db = mongojs('mongodb://alfa:alfa1963@ds159880.mlab.com:59880/bdviagens', ['viagens']);


var viagem = {
    Pais: { type: String, required: true },
    Cidade: String,
    Localizacao: { coordinates: [,]},
    Descricao: String,
    Visivel: { type: Boolean, default: false },
    Chegada: { type: Date },
    Partida: { type: Date },
    idUtilizador: String,
};

/* GET ALL     /viagens */
router.get('/viagens', function (req, res, next) {
    db.viagens.find(function (err, viagens) {
        if (err) { res.send(err); }
        console.log('Todas as viagens: ' + JSON.stringify(viagens));
        res.json(viagens);
    });
});

/* GET ONE   /viagens/id */
router.get('/viagens/:id', function (req, res, next) {
    db.viagens.findOne({ _id: mongojs.ObjectId(req.params.id) }, function (err, viagem) {
        if (err) { res.send(err); }
        console.log('Viagem id: ' + JSON.stringify(viagem));
        res.json(viagem);
    });
});


/* DELETE    /viagens/id */
router.delete('/viagens/:id', function (req, res, next) {
    db.viagens.remove({ _id: mongojs.ObjectId(req.params.id) }, function (err, viagen) {
        if (err) { res.send(err); }
        console.log('Viagem retirada: ' + JSON.stringify(viagem));
        res.json(viagen);
    });
});

/* POST /viagens */
router.post('/viagens', function (req, res) {
    viagem = req.body;
    db.viagens.insert(viagem, function (err, viagem) {
        if (err) {
            res.send({ 'erro': 'Ocorreu um erro' });
        } else {
            console.log('Viagem inserida: ' + JSON.stringify(viagem));
            res.send(viagem);
        }
    });
});

/* PUT     /viagens/id */
router.put('/viagens/:id', function (req, res) {
    var Descricao = req.body.Descricao;
    console.log(JSON.stringify(viagem));
    db.viagens.update({ _id: mongojs.ObjectId(req.params.id) }, { $set: { Descricao } }, function (err, resultado) {
        if (err) {
            res.send({ 'erro': 'Ocorreu um erro' });
        } else {
            console.log('' + resultado + 'Viagem alterada');
            res.send(viagem);
        }
    });
});

module.exports = router;