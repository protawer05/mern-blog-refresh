import express from 'express'
import jwt from 'jsonwebtoken'
import mongoose from 'mongoose'
import { registerValidation } from './validations/auth.js'
import { validationResult } from 'express-validator'
import UserModel from './models/User.js'
import bcrypt from 'bcrypt'
const app = express()
mongoose
	.connect('mongodb+srv://gasper:220767@cluster0.jj7c0xv.mongodb.net/blog?retryWrites=true&w=majority')
	.then(() => {
		console.log(`DB is ok`)
	})
	.catch(err => `db is err: ${err}`)
app.use(express.json())

app.post('/auth/register', registerValidation, async (req, res) => {
	try {
		const errors = validationResult(req)
		if (!errors.isEmpty()) {
			return res.status(400).json(errors.array())
		}
		const password = req.body.password
		const salt = await bcrypt.genSalt(10)
		const hash = await bcrypt.hash(password, salt)
		const doc = new UserModel({
			email: req.body.email,
			fullName: req.body.fullName,
			passwordHash: hash,
			avatarUrl: req.body.avatarUrl,
		})
		const user = await doc.save()
		const token = jwt.sign({ _id: user._id }, 'secret123', { expiresIn: '30d' })

		const { passwordHash, ...userData } = user._doc

		res.json({ ...userData, token })
	} catch (err) {
		console.log(err)
		res.json({ msg: err }).status(500)
	}
})

app.listen(4444, err => {
	err ? console.log(err) : console.log('server is ok')
})
