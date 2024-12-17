const express = require('express')
const sqlite3 = require('sqlite3').verbose()
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const {open} = require('sqlite')

const app = express()
app.use(express.json())

const dbPath = './twitterClone.db'
let db

// Initialize database
const initializeDB = async () => {
  try {
    db = await open({filename: dbPath, driver: sqlite3.Database})
    console.log('Database connected successfully')
    app.listen(3000, () => {
      console.log('Server Running at http://localhost:3000/')
    })
  } catch (e) {
    console.error(`DB Error: ${e.message}`)
    process.exit(1)
  }
}
initializeDB()

// JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization
  if (!authHeader) return res.status(401).send('Invalid JWT Token')

  const token = authHeader.split(' ')[1]
  jwt.verify(token, 'SECRET_KEY', (err, user) => {
    if (err) return res.status(401).send('Invalid JWT Token')
    req.user = user
    next()
  })
}

// API 1: Register User
app.post('/register/', async (req, res) => {
  const {username, password, name, gender} = req.body
  const userQuery = `SELECT * FROM user WHERE username = ?`

  const dbUser = await db.get(userQuery, [username])
  if (dbUser) {
    return res.status(400).send('User already exists')
  }

  if (password.length < 6) {
    return res.status(400).send('Password is too short')
  }

  const hashedPassword = await bcrypt.hash(password, 10)
  const insertUserQuery = `
    INSERT INTO user (username, password, name, gender) 
    VALUES (?, ?, ?, ?);
  `
  await db.run(insertUserQuery, [username, hashedPassword, name, gender])
  res.send('User created successfully')
})

// API 2: Login User
app.post('/login/', async (req, res) => {
  const {username, password} = req.body
  const userQuery = `SELECT * FROM user WHERE username = ?`

  const dbUser = await db.get(userQuery, [username])
  if (!dbUser) {
    return res.status(400).send('Invalid user')
  }

  const isPasswordValid = await bcrypt.compare(password, dbUser.password)
  if (!isPasswordValid) {
    return res.status(400).send('Invalid password')
  }

  const jwtToken = jwt.sign({userId: dbUser.user_id}, 'SECRET_KEY')
  res.send({jwtToken})
})

// API 3: Get Tweets Feed
app.get('/user/tweets/feed/', authenticateToken, async (request, response) => {
  const userId = request.user.userId
  console.log(userId)
  const getTweetsQuery = `
    SELECT user.username AS username, tweet.tweet, tweet.date_time AS dateTime
    FROM follower
    INNER JOIN tweet ON follower.following_user_id = tweet.user_id
    INNER JOIN user ON tweet.user_id = user.user_id
    WHERE follower.follower_user_id = ?
    ORDER BY tweet.date_time DESC
    LIMIT 4;
  `

  const tweets = await db.all(getTweetsQuery, [userId])
  response.send(tweets)
})

// API 4: Get Following List
app.get('/user/following/', authenticateToken, async (req, res) => {
  const userId = req.user.userId
  const query = `
    SELECT name 
    FROM user 
    INNER JOIN follower ON user.user_id = follower.following_user_id
    WHERE follower.follower_user_id = ?;
  `
  const result = await db.all(query, [userId])
  res.send(result)
})

// API 5: Get Followers List
app.get('/user/followers/', authenticateToken, async (req, res) => {
  const userId = req.user.userId
  const query = `
    SELECT name 
    FROM user 
    INNER JOIN follower ON user.user_id = follower.follower_user_id
    WHERE follower.following_user_id = ?;
  `
  const result = await db.all(query, [userId])
  res.send(result)
})

// API 6: Get Specific Tweet
app.get('/tweets/:tweetId/', authenticateToken, async (request, response) => {
  const {tweetId} = request.params
  const userId = request.user.userId

  // SQL Query to validate whether the user follows the tweet's author
  const validateTweetQuery = `
    SELECT 
      tweet.user_id AS userId
    FROM 
      tweet INNER JOIN follower 
      ON tweet.user_id = follower.following_user_id
    WHERE 
      tweet.tweet_id = ? AND follower.follower_user_id = ?;
  `

  const tweet = await db.get(validateTweetQuery, [tweetId, userId])

  if (tweet === undefined) {
    return response.status(401).send('Invalid Request')
  }

  // SQL Query to get tweet details
  const getTweetDetailsQuery = `
    SELECT 
      tweet.tweet,
      COUNT(DISTINCT like.like_id) AS likes,
      COUNT(DISTINCT reply.reply_id) AS replies,
      tweet.date_time AS dateTime
    FROM 
      tweet
      LEFT JOIN like ON tweet.tweet_id = like.tweet_id
      LEFT JOIN reply ON tweet.tweet_id = reply.tweet_id
    WHERE 
      tweet.tweet_id = ?;
  `

  const tweetDetails = await db.get(getTweetDetailsQuery, [tweetId])
  response.send(tweetDetails)
})

// API 7: Get Likes on Tweet
app.get('/tweets/:tweetId/likes/', authenticateToken, async (req, res) => {
  const userId = req.user.userId
  const {tweetId} = req.params

  const accessQuery = `
    SELECT * 
    FROM tweet 
    INNER JOIN follower ON tweet.user_id = follower.following_user_id
    WHERE follower.follower_user_id = ? AND tweet.tweet_id = ?;
  `
  const tweetAccess = await db.get(accessQuery, [userId, tweetId])

  if (!tweetAccess) {
    return res.status(401).send('Invalid Request')
  }

  const likeQuery = `
    SELECT user.username 
    FROM like 
    INNER JOIN user ON like.user_id = user.user_id 
    WHERE like.tweet_id = ?;
  `
  const likes = await db.all(likeQuery, [tweetId])
  res.send({likes: likes.map(user => user.username)})
})

// API 8: Get List of Replies to a Tweet
app.get('/tweets/:tweetId/replies/', authenticateToken, async (req, res) => {
  const userId = req.user.userId
  const {tweetId} = req.params

  const accessQuery = `
    SELECT * 
    FROM tweet 
    INNER JOIN follower ON tweet.user_id = follower.following_user_id
    WHERE follower.follower_user_id = ? AND tweet.tweet_id = ?;
  `
  const tweetAccess = await db.get(accessQuery, [userId, tweetId])

  if (!tweetAccess) {
    return res.status(401).send('Invalid Request')
  }

  const replyQuery = `
    SELECT user.name, reply.reply 
    FROM reply 
    INNER JOIN user ON reply.user_id = user.user_id 
    WHERE reply.tweet_id = ?;
  `
  const replies = await db.all(replyQuery, [tweetId])
  res.send({replies})
})

// API 9: Get User's Tweets
app.get('/user/tweets/', authenticateToken, async (req, res) => {
  const userId = req.user.userId

  const query = `
    SELECT tweet, 
      (SELECT COUNT(*) FROM like WHERE tweet_id = tweet.tweet_id) AS likes,
      (SELECT COUNT(*) FROM reply WHERE tweet_id = tweet.tweet_id) AS replies,
      date_time AS dateTime
    FROM tweet WHERE user_id = ?`
  const tweets = await db.all(query, userId)
  res.send(tweets)
})

// API 10: Create a Tweet
app.post('/user/tweets/', authenticateToken, async (req, res) => {
  const {user_id} = req.user
  const {tweet} = req.body

  const query = `INSERT INTO tweet (tweet, user_id, date_time) VALUES (?, ?, ?)`
  await db.run(query, [tweet, user_id, new Date().toISOString()])
  res.send('Created a Tweet')
})

// API 11: Delete a Tweet
app.delete(
  '/tweets/:tweetId/',
  authenticateToken,
  async (request, response) => {
    try {
      const {tweetId} = request.params
      const {userId} = request.user // JWT-decoded userId
      console.log(`UserID: ${userId}, TweetID: ${tweetId}`)

      // Step 1: Check if the tweet exists and belongs to the current user
      const checkTweetQuery = `
        SELECT *
        FROM tweet
        WHERE tweet_id = ?;
      `
      const tweet = await db.get(checkTweetQuery, [tweetId])
      console.log(tweet)
      // If tweet does not exist
      if (!tweet) {
        return response.status(404).send('Tweet does not exist')
      }

      // Check ownership
      if (tweet.user_id !== userId) {
        return response.status(401).send('Invalid Request')
      }

      // Step 2: Delete the tweet
      const deleteTweetQuery = `
        DELETE FROM tweet
        WHERE tweet_id = ?;
      `
      await db.run(deleteTweetQuery, [tweetId])

      response.status(200).send('Tweet Removed')
    } catch (error) {
      console.error(`Error: ${error.message}`)
      response.status(500).send('Internal Server Error')
    }
  },
)

module.exports = app
