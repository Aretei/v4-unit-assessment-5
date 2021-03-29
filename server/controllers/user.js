const bcrypt = require('bcryptjs')

module.exports = {
    register: async (req, res) => {
        const db = req.app.get('db')

        const { username, password } = req.body

        const result = await db.find_user_by_username([username])
        const existingUser = result[0]
        
        if(existingUser) {
            return res.status(409).send('user already exists')
        }
        else {
            const salt = bcrypt.genSaltSync(10)
            const hash = bcrypt.hashSync(password, salt)
            const registerUser = await db.create_user([username, hash, `https://robohash.org/${username}.png`])
            const user = registerUser[0]
            req.session.user = {
                id: user.id,
                username: user.username,
                password: user.password,
                profile_pic: user.profile_pic
            }
        }
    },

    login: async (req, res) => {
        const db = req.get.app('db')
        const { username, password } = req.body
        db.find_user_by_username(username)
            .then(([exisitingUser]) => {
                if(!exisitingUser) {
                    return res.status(403).send('wrong username')
                }

                const isAuthenticated = bcrypt.compareSync(password, exisitingUser.hash)

                if(!isAuthenticated) {
                    return res.status(403).send('incorrect password :)')
                }

                delete exisitingUser.hash
                req.session.user = exisitingUser
                res.status(200).send(req.session.user)

            })
    }

}