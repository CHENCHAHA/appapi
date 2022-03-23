const express = require('express')
const fs = require('fs')
const path = require('path')
const cors = require('cors')
const mysql = require('mysql')
const bodyParser = require('body-parser')
    //定义对密码加密
const bcryptjs = require('bcryptjs')
    // 导入 Joi 来定义验证规则
const Joi = require('joi')
    // 1. 导入 @escook/express-joi
const expressJoi = require('@escook/express-joi')
    //生成token字符串
const jwt = require('jsonwebtoken')
    //解析token字符串
const expressjwt = require('express-jwt')
const multer = require('multer')
const { syncBuiltinESMExports } = require('module')
    // Multer 是一个 node.js 处理的中间件multipart/form-data，主要用于上传文件。它被写在busboy的顶部以获得最大的效率。

const url = 'http://127.0.0.1/'


const app = express()
    //定义图片上传到服务器位置，已经定义保存文件名
    //start
const nowtime = Date.now()
const storage = multer.diskStorage({
    destination: function(req, file, cb) {
        cb(null, 'img/'); // 他会放在当前目录下的 /upload 文件夹下（没有该文件夹，就新建一个）
    },

    filename: function(req, file, cb) { // 在这里设定文件名
        cb(null, nowtime + '+' + file.originalname); // file.originalname是将文件名设置为上传时的文件名，file中携带的
        // cb(null, Date.now() + '-' + file.originalname) // 加上Date.now()可以避免命名重复
    }
})
const storage1 = multer.diskStorage({
    destination: function(req, file, cb) {
        cb(null, 'user_touxiang/'); // 他会放在当前目录下的 /upload 文件夹下（没有该文件夹，就新建一个）
    },

    filename: function(req, file, cb) { // 在这里设定文件名
        cb(null, nowtime + '+' + file.originalname); // file.originalname是将文件名设置为上传时的文件名，file中携带的
        // cb(null, Date.now() + '-' + file.originalname) // 加上Date.now()可以避免命名重复
    }
})
const upload = multer({ storage: storage }) //存储地址
const upload1 = multer({ storage: storage1 }) //存储地址
    //end
app.use(cors())
app.use(express.urlencoded({ extended: false }))
app.use(express.static(__dirname))
app.use(bodyParser.json())
    //定义token中间件
app.use(expressjwt({
    //生成token密匙
    secret: 'chenchao',
    algorithms: ['HS256']
}).unless({
    //指定路径请求不经过token解析。
    path: ['/login', '/register', '/api/usermessage', '/api/chongmsg', '/api/chongli', '/api/chongimg', '/api/uploadpetsmsg', '/api/uploadusertouxiang', '/api/uploadchongmsg', '/api/shopping', '/api/shoppingdata', '/api/delectshop', '/api/changeusername', '/api/changeusergexin', '/api/changeaddress', '/api/changepassword']
}))

app.listen(80, () => {
    console.log('80端口监听中')
})

const db = mysql.createConnection({
    host: '127.0.0.1',
    user: 'root',
    password: '123456',
    database: 'appapi'
})


//定义验证规则
const userschema = {
    body: {
        username: Joi.string().pattern(/^[\S]{8,12}$/).required().error(new Error('账号必须为8-12位字符..')), //[\S]表示除去一切空格
        password: Joi.string().pattern(/(?=.*\d)(?=.*[a-z])(?=.*[A-Z])[a-zA-Z0-9]{8,12}$/).required().error(new Error('密码必须包含大小写字母和数字，长度在8-12之间')), //密码必须包含大小写字母和数字的组合，不能使用特殊字符，长度在8-12之间
        repassword: Joi.ref('password'),
        oldpassword: Joi.string().pattern(/(?=.*\d)(?=.*[a-z])(?=.*[A-Z])[a-zA-Z0-9]{8,12}$/).error(new Error('密码必须包含大小写字母和数字')), //密码必须包含大小写字母和数字的组合，不能使用特殊字符，长度在8-12之间
    }
}


app.post('/register', expressJoi(userschema), (req, res) => {
    //验证数据是否存在相同的用户名
    console.log(req.body);
    const sqlstr = 'select * from user_login where username=?'
    db.query(sqlstr, [req.body.username], (err, results) => {

        if (err) {
            return res.send({ message: err.message })
        }
        //如果有用户
        if (results.length === 1) {
            return res.send({
                status: 1,
                message: '用户名已经存在，请重试'
            })
        } else {
            //执行注册操作
            /**
             * 加密处理 - 同步方法
             * bcryptjs.hashSync(data, salt)
             *    - data  要加密的数据
             *    - slat  用于哈希密码的盐。如果指定为数字，则将使用指定的轮数生成盐并将其使用。推荐 10
             */
            //因为用户刚注册，没有名称，头像，个性签名，所以数据库需要自动存入
            const user_touxiang = url + 'user_touxiang/testtouxiang.png'
            const user_name = req.body.username
            const user_gexin = '小主！取个好听的个性签名吧'
            let haspwd = bcryptjs.hashSync(req.body.password, 10)
                //将用户名和加密后的密码存入数据库
            const sqlstrin = 'insert into user_login (username,password,user_touxiang,user_name,user_gexin) values (?,?,?,?,?)'
            db.query(sqlstrin, [req.body.username, haspwd, user_touxiang, user_name, user_gexin], (err, results) => {
                if (err) {
                    return res.send(err.message)
                }
                //如果插入数据成功
                if (results.affectedRows === 1) {
                    return res.send({
                        status: 0,
                        message: '注册成功'
                    })
                }

            })
        }
    })
})


//用户登录
app.post('/login', expressJoi(userschema), (req, res) => {
    const sqlstrlog = 'select * from user_login where username=?'
    let token = jwt.sign({ username: req.body.username }, 'chenchao', { expiresIn: '1h' })
    db.query(sqlstrlog, [req.body.username], (err, results) => {
        console.log(results);
        if (results.length != 1) {
            return res.send({
                status: 1,
                message: '登录失败，请检查账号和密码'
            })
        } else {
            let comparepwd = bcryptjs.compareSync(req.body.password, results[0].password)
            if (err) {
                return res.send({
                    status: 1,
                    message: err.message
                })
            }
            if (comparepwd) {
                res.send({
                    status: 0,
                    message: '登录成功',
                    token: token,
                    user_touxiang: results[0].user_touxiang,
                    user_name: results[0].user_name,
                    user_gexin: results[0].user_gexin

                })
            } else {
                res.send({
                    status: 1,
                    message: '登录失败，请检查账号和密码'
                })
            }
        }

    })
})

//修改密码;
app.post('/api/changepassword', expressJoi(userschema), (req, res) => {
        console.log(req.body)
        const sqlstrlog = 'select * from user_login where username=?'
        db.query(sqlstrlog, [req.body.username], (err, results) => {
            console.log(results);
            if (results.length != 1) {
                return res.send({
                    status: 1,
                    message: '账号不存在,请联系管理员'
                })
            } else {
                let compar = bcryptjs.compareSync(req.body.oldpassword, results[0].password)
                if (err) {
                    return res.send({
                        status: 1,
                        message: err.message
                    })
                }
                if (compar) {
                    //执行修改密码的操作
                    const sqlchangepassword = 'update user_login set password=? where username=?'
                    let newpwd = bcryptjs.hashSync(req.body.password, 10) //加密
                    db.query(sqlchangepassword, [newpwd, req.body.username], (err, results) => {
                        if (err) {
                            return res.send(err.message)
                        }
                        //如果插入数据成功
                        if (results.affectedRows === 1) {
                            return res.send({
                                status: 0,
                                message: '修改密码成功'
                            })
                        } else {
                            return res.send({
                                status: 1,
                                message: '修改密码失败'
                            })
                        }
                    })
                } else {
                    res.send({
                        status: 1,
                        message: '原密码错误'
                    })
                }
            }

        })
    })
    /* 新增 */
    //轮播图
app.get('/api/lunbo', (req, res) => {
    res.send({
        status: 200,
        message: '获取轮播图成功',
        image: []
    })
})

//宠物列表api
app.get('/api/chongli', (req, res) => {
    console.log('发送过来请求了');
    const sql = 'select * from chongmsg'
    db.query(sql, (err, results) => {
        console.log(results);
        if (results.length == 0) {
            return res.send({
                status: 1,
                message: '无数据'
            })
        } else {
            if (err) {
                return res.send({
                    status: 1,
                    message: err.message
                })
            }
            if (results.length >= 0) {

                return res.send({
                    status: 0,
                    message: '查询成功',
                    results: results
                })
            } else {
                return res.send({
                    status: 1,
                    message: '失败'
                })
            }
        }

    })
})

//根据用户名获取用户信息
app.post('/api/usermessage', (req, res) => {
    const sqlmessage = 'select * from user_login where username=?'
    db.query(sqlmessage, [req.body.username], (err, results) => {
        if (err) {
            return res.send({
                status: 1,
                message: err.message
            })
        }
        if (results.length != 1) {
            res.send({
                status: 1,
                message: '出错了,请检查username'
            })
        } else {
            res.send({
                status: 0,
                message: '获取用户信息成功',
                data: results
            })
        }
    })
})



//宠物信息查询api
app.post('/api/chongmsg', (req, res) => {
    console.log('发送过来请求了');
    const sql = 'select * from chongmsg where url=?'
    db.query(sql, [req.body.url], (err, results) => {
        if (results.length != 1) {
            return res.send({
                status: 1,
                message: '运行出错，请检查url'
            })
        } else {
            if (err) {
                return res.send({
                    status: 1,
                    message: err.message
                })
            }
            if (results.length >= 0) {
                res.send({
                    status: 0,
                    message: '查询成功',
                    results: results
                })
            } else {
                res.send({
                    status: 1,
                    message: '失败'
                })
            }
        }

    })
})

//宠物图片请求
app.post('/api/chongimg', (req, res) => {
    console.log('发送过来图片请求了');
    console.log(req.body.url)
    const sql = 'select * from chongimg where url=?'
    db.query(sql, [req.body.url], (err, results) => {
        console.log(results);
        if (results.length == 0) {
            return res.send({
                status: 1,
                message: '运行出错，请检查url....'
            })
        } else {
            if (err) {
                return res.send({
                    status: 1,
                    message: err.message
                })
            }
            if (results.length >= 0) {
                res.send({
                    status: 0,
                    message: '查询成功',
                    results: results
                })
            } else {
                res.send({
                    status: 1,
                    message: '失败'
                })
            }
        }

    })
})

//发布请求，存储到数据库
app.post('/api/uploadchongmsg', (req, res) => {

    const charuchongmsg = 'insert into chongmsg (url,user_name,username,text,text_msg,price,user_touxiang,dizhi) values(?,?,?,?,?,?,?,?)'

    db.query(charuchongmsg, [req.body.url, req.body.user_name, req.body.username, req.body.text, req.body.text_msg, req.body.price, req.body.user_touxiang, req.body.dizhi], (err, results) => {
        if (err) {
            return res.send({ message: err.message })
        }
        if (results.affectedRows === 1) {
            return res.send({
                status: 0,
                message: '发布成功'
            })
        } else {
            return res.send({
                status: 1,
                message: '发布失败'
            })
        }

    })
})

//接收第一张预览图片地址
/* app.post('/api/uploadprimg', (req, res) => {
        console.log('body', req.body)

        const charuprimg = 'insert into chongmsg (preview) values(?) where url=?'
            db.query(charuprimg, [req.body.preview, req.body.url], (err, results) => {
                if (err) {
                    return res.send({ message: err.message })
                }
                if (results.affectedRows === 1) {
                    return res.send({
                        status: 0,
                        message: '预览地址图片插入成功'
                    })
                } else {
                    return res.send({
                        status: 1,
                        message: '预览图片插入失败'
                    })
                }

            })
    }) */
//携带多个参数包括图片需要存储到服务器
app.post('/api/uploadpetsmsg', upload.single('file'), (req, res) => {
    console.log(req.body, req.file)
        //直接插入宠物信息表
        /**
         * 因为前端需要多次请求该接口，将用户所有照片上传
         * 所以，第一次上传，没有url，后面上传，已经存在url
         * 所以，1. 需要先查找数据库中是否存在url。
         * 2.如果不存在，直接插入新数据，。
         * 3.如果存在，则找到该url，修改图片存储信息，像后面加另一个图片地址，用，链接。
         * 4.如果前端要取，则用，分隔取用
         */
    const charutupian = 'insert into chongimg (url,chongimg) values(?,?)'
    const xinghaha = url + 'img/' + nowtime + '+' + req.file.originalname
        /* const chaxunurl = 'select * from chongimg where url=?' */
    db.query(charutupian, [req.body.url, xinghaha], (err, results) => {
        if (err) {
            return res.send({ message: err.message })
        }
        //如果不存在url
        if (results.affectedRows == 1) {
            return res.send({
                    status: 0,
                    message: '图片插入成功'
                })
                //将图片信息上传到数据库同时还有前端传过来的url，url为每个发布的id
                //const xinghaha = url + 'img/' + nowtime + '+' + req.file.originalname
                //const insertimgurlsql = 'insert into chongimg (url,chongimg) values (?,?)'
                /* db.query(insertimgurlsql, [req.body.url, xinghaha], (err, results) => {
                    if (err) {
                        return res.send({ message: err.message })
                    }
                    if (results.affectedRows == 1) {
                        return res.send({
                            status: 0,
                            message: '图片插入成功'
                        })
                    }
                }) */
        }
        //存在url
        else {
            res.send({
                    status: 1,
                    message: '出错了，检查'
                })
                //存在url，对该url中的chongimg字段进行拼接
                /* const newimg = url + 'img/' + Date.now() + '+' + req.file.originalname
                const xiugaichongimg = 'update chongimg set chongimg=concat(?,chongimg) where url=?'
                db.query(xiugaichongimg, [newimg, req.body.url], (err, results) => {
                    if (err) {
                        return res.send({ message: err.message })
                    }
                    if (results.affectedRows == 1) {
                        return res.send({
                            status: '0',
                            message: '图片拼接成功'
                        })
                    }
                }) */
        }

    })
})

//修改头像，上传新头像，删除旧头像操作。
app.post('/api/uploadusertouxiang', upload1.single('filehead'), (req, res) => {
    const charutouxiang = 'update user_login set user_touxiang=? where username=?'
    const touxiang = url + 'user_touxiang/' + nowtime + '+' + req.file.originalname
    db.query(charutouxiang, [touxiang, req.body.username], (err, results) => {
        if (err) {
            return res.send({ message: err.message })
        }
        //如果不存在url
        if (results.affectedRows == 1) {
            return res.send({
                status: 0,
                message: '头像修改成功',
                user_touxiang: touxiang
            })
        } else {
            res.send({
                status: 1,
                message: '修改头像出错,请重试'
            })
        }

    })
})

//修改用户名称
app.post('/api/changeusername', (req, res) => {
    const sqlusername = 'update user_login set user_name=? where username=?'
    db.query(sqlusername, [req.body.user_name, req.body.username], (err, results) => {
        if (err) {
            return res.send({ message: err.message })
        }
        if (results.affectedRows == 1) {
            return res.send({
                status: 0,
                message: '修改用户名称成功'
            })
        } else {
            res.send({
                status: 1,
                message: '修改用户名称失败,请重试'
            })
        }
    })
})

//修改用户个性签名
app.post('/api/changeusergexin', (req, res) => {
    const sqlusername = 'update user_login set user_gexin=? where username=?'
    db.query(sqlusername, [req.body.user_gexin, req.body.username], (err, results) => {
        if (err) {
            return res.send({ message: err.message })
        }
        if (results.affectedRows == 1) {
            return res.send({
                status: 0,
                message: '修改用户名个性签名成功'
            })
        } else {
            res.send({
                status: 1,
                message: '修改用户个性签名失败,请重试'
            })
        }
    })
})

//修改用户地址
app.post('/api/changeaddress', (req, res) => {
    const sqlusername = 'update user_login set user_address=? where username=?'
    db.query(sqlusername, [req.body.user_address, req.body.username], (err, results) => {
        if (err) {
            return res.send({ message: err.message })
        }
        if (results.affectedRows == 1) {
            return res.send({
                status: 0,
                message: '修改用户地址成功'
            })
        } else {
            res.send({
                status: 1,
                message: '修改用户地址失败,请重试'
            })
        }
    })
})

//点击我想要发起添加到购物车的请求
app.post('/api/shopping', (req, res) => {
    const sqlshopping = 'select * from user_cart where url=?'
    db.query(sqlshopping, [req.body.url], (err, results) => {
        if (err) {
            return res.send({ message: err.message })
        }
        if (results.length >= 1) {
            return res.send({
                status: 1,
                message: '你已经添加到购物车,无需再次添加'
            })
        } else {
            //如果没有添加到购物车，对该商品的url信息进行插入
            const sqlshoppingcart = 'insert into user_cart (username,url) values(?,?)'
            db.query(sqlshoppingcart, [req.body.username, req.body.url], (err, results) => {
                if (err) {
                    return res.send({ message: err.message })
                }
                if (results.affectedRows == 1) {
                    return res.send({
                        status: 0,
                        message: '恭喜小主,添加成功'
                    })
                }
            })
        }
    })
})

//获取每位用户购物车数据的请求api
app.post('/api/shoppingdata', (req, res) => {
    const sqlshoppingdata = 'select * from user_cart where username=?'
    db.query(sqlshoppingdata, [req.body.username], (err, results) => {
        if (err) {
            return res.send({ message: err.message })
        }
        if (results.length == 0) {
            return res.send({
                status: 1,
                message: '小主,你的购物车是空的'
            })
        } else {
            console.log('ressssss', results);
            //查询对于url的商品数据
            const sqlcartdata = 'select * from user_cart inner join chongmsg on user_cart.url=chongmsg.url'
                //for (var i = 0; i <= results.length; i++) {
            db.query(sqlcartdata, (err, results) => {
                    if (err) {
                        return res.send({ message: err.message })
                    } else {
                        /* const sqlcartimg = 'select * from chongimg where url=?'
                        for (var i = 0; i <= results.length; i++) {
                            db.query(sqlcartimg, [results[i].url], (err, results) => {
                                if (err) {
                                    return res.send({ message: err.message })
                                } else {
                                    res.send({
                                        status: 0,
                                        message: '商品图片',
                                        img: results[0]
                                    })
                                }
                            })
                        } */
                        res.send({
                            status: 0,
                            message: '商品信息',
                            data: results
                        })
                    }
                })
                // }
                /* res.send({
                    status: 0,
                    message: '788888',
                    data: results
                }) */
        }
    })
})

//删除购物车内容
app.post('/api/delectshop', (req, res) => {
    const sqdelect = 'delete from user_cart where url=?'
    db.query(sqdelect, [req.body.url], (err, results) => {
        if (err) {
            return res.send({ message: err.message })
        }
        if (results.affectedRows == 1) {
            res.send({
                status: 0,
                message: '删除商品成功!'
            })
        } else {
            res.send({
                status: 1,
                message: '删除数据失败!'
            })
        }
    })
})






//
app.use((err, req, res, next) => {
    //Joi校验失败
    if (err instanceof Joi.ValidationError) {
        return res.send({
            status: 1,
            message: err.message
        })
    }
    //未知错误
    res.send({
        status: 1,
        message: err.message
    })
})