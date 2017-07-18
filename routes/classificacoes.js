var express = require('express');
var router = express.Router();
var fs = require("fs");
var jsonfile = require('jsonfile')
var mongojs = require('mongojs');
// the db is on a remote server (the port default to mongo) 
var db = mongojs('mongodb://alfa:alfa1963@ds159880.mlab.com:59880/bdviagens', ['classificacoes']);


var classificacao = {
    Classi: { type: Number },
    Data: { type: Date },
    idViagem: { type: String, required: true },
    idMomento: { type: String },
    idUtilizador: { type: String },
};


/* GET ALL     /classificacoes */
router.get('/classificacoes', function (req, res, next) {
    db.classificacoes.find(function (err, classificacoes) {
        if (err) { res.send(err); }
        console.log('Todas as classificacoes: ' + JSON.stringify(classificacoes));
        res.json(classificacoes);
    });
});


/* DELETE    /classificacoes/id */
router.delete('/classificacoes/:id', function (req, res, next) {
    db.classificacoes.remove({ _id: mongojs.ObjectId(req.params.id) }, function (err, classificacao) {
        if (err) { res.send(err); }
        console.log('classificacao retirada: ' + JSON.stringify(classificacao));
        res.json(classificacao);
    });
});

/* POST     /classificacoes */
router.post('/classificacoes', function (req, res) {
    classificacao = req.body;
    db.classificacoes.insert(classificacao, function (err, classificacao) {
        if (err) {
            res.send({ 'erro': 'Ocorreu um erro' });
        } else {
            console.log('classificacao inserida: ' + JSON.stringify(classificacao));
            res.send(classificacao);
        }
    });
});

/* GET ONE       /classificacoes/id/viagens*/
router.get('/classificacoes/:id', function (req, res, next) {
    db.classificacoes.find({ idViagem: req.params.id }, function (err, classificacao) {
        if (err) { res.send(err); }
        var A = 0;
        var B = 0;
        var C = 0;
        for (var i = 0; i < classificacao.length; i++) {
            if (classificacao[i].Classi == 1)
            { A = A + 1; }
            if (classificacao[i].Classi == 2)
            { B = B + 1; }
            if (classificacao[i].Classi == 3)
            { C = C + 1; }
        }
        notas = '  Ja fui muito feliz aqui = ' + A + '  Nunca tinha experimentado, estou maravilhado! = ' + B + '  Esta vai direto para minha bucket list! = ' + C
        res.json({ viagem: classificacao, classificacao: notas });
    });
});


module.exports = router;
