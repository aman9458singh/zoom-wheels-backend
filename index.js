const express = require('express')
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');

const { check, validationResult } = require('express-validator');
const cors = require('cors')
const jwt = require('jsonwebtoken');
const { buildQueryFromParams, validateContactUs, sendEmail } = require('./helpers');
require('dotenv').config();
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

const app = express()
const port = process.env.PORT || 5000

// MongoDB
const uri = `mongodb+srv://${process.env.SECRET_USER}:${process.env.SECRET_PASSWORD}@cluster0.dtgfo3e.mongodb.net/?retryWrites=true&w=majority`;
const client = new MongoClient(uri, { useNewUrlParser: true, useUnifiedTopology: true, serverApi: ServerApiVersion.v1 });

// middlewares
app.use(cors())
app.use(express.json())

function verifyJWT(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).send({ message: 'unauthorized access' });
  }
  const token = authHeader.split(' ')[1];

  jwt.verify(token, process.env.SECRET_ACCESS_TOKEN, function (err, decoded) {
    if (err) {
      return res.status(403).send({ message: 'forbidden access' });
    }
    req.decoded = decoded;
    next();
  })
}

async function run() {
  try {
    const usersCollection = client.db('arjanMotors').collection('users');
    const brandsCollection = client.db('arjanMotors').collection('productBrands');
    const brandsAndModel = client.db('arjanMotors').collection('brands-model');
    const categoriesCollection = client.db('arjanMotors').collection('productCategories');
    const productsCollection = client.db('arjanMotors').collection('products');
    const blogsCollection = client.db('arjanMotors').collection('blogs');
    const bookingCollection = client.db('arjanMotors').collection('booking');
    const feedbacksCollection = client.db('arjanMotors').collection('feedbacks');
    const paymentsCollection = client.db('arjanMotors').collection('payments');

    const verifyAdmin = async (req, res, next) => {
      const decodedUID = req.decoded.uid;
      const query = { uid: decodedUID };
      const user = await usersCollection.findOne(query);
      console.log(decodedUID)
      if (user?.userType !== 'admin') {
        return res.status(403).send({ message: 'forbidden access' })
      }
      next();
    }

    // POST route to save feedback
    app.post('/feedback', async (req, res) => {
      try {
        const { name, rating, feedback, contactNumber } = req.body;
        if (!name || !rating || !feedback || !contactNumber) {
          return res.status(400).json({
            message: 'Missing required fields',
            fieldsStatus: { name, rating, feedback, contactNumber }
          });
        }
        await feedbacksCollection.insertOne({ ...req.body, createdDate: new Date().getTime(), approved: false })
        res.status(201).json({ message: 'Feedback saved successfully' });
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Error saving feedback' });
      }
    });


    // GET route to fetch all feedback (including approved status)
    app.get('/feedback', verifyJWT, verifyAdmin, async (req, res) => {
      try {
        const feedback = await feedbacksCollection.find({}).sort({ createdDate: -1 }).toArray();
        res.json(feedback);
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Error fetching feedback' });
      }
    });


    // GET route to fetch all feedback (including approved status)
    app.get('/happy-customers', async (req, res) => {
      try {
        const projection = { contactNumber: 0 }; // Exclude contact number if desired
        const feedback = await feedbacksCollection.find({ approved: true })
          .project(projection)
          .sort({ createdDate: -1 })
          .toArray();
        res.json(feedback);
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Error fetching feedback' });
      }
    });

    // PUT route to approve feedback (requires admin access or authorization)
    app.put('/feedback/:id/approve', verifyJWT, verifyAdmin, async (req, res) => {
      const feedbackId = req.params.id;
      try {
        const filter = { _id: ObjectId(feedbackId) }
        const options = { upsert: true };
        const udpateData = {
          $set: {
            approved: true
          }
        }
        const feedback = await feedbacksCollection.updateOne(filter, udpateData, options)
        if (!feedback) {
          return res.status(404).json({ message: 'Feedback not found' });
        }
        res.json({ message: 'Feedback approved successfully' });
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Error approving feedback' });
      }
    });

    // DELETE route to delete feedback by ID (requires admin access or authorization)
    app.delete('/feedback/:id', verifyJWT, verifyAdmin, async (req, res) => {
      const feedbackId = req.params.id;
      try {
        const filter = { _id: ObjectId(feedbackId) };
        const feedback = await feedbacksCollection.deleteOne(filter);
        if (!feedback) {
          return res.status(404).json({ message: 'Feedback not found' });
        }
        res.json({ message: 'Feedback deleted successfully' });
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Error deleting feedback' });
      }
    });

    // PRODUCT API
    app.get('/products', async (req, res) => {
      const start = req.query.start || 0;
      const query = { ...req.query, reportStatus: false, };
      const searchQuery = req.query.search;
      console.log(req.query, 'searchQuery')
      const projection = { contactNumber: 0 };
      if (searchQuery) {
        const query = {
          $or: [
            { carBrand: { $regex: searchQuery, $options: 'i' } }, // Case-insensitive regex search for carBrand
            { carModel: { $regex: searchQuery, $options: 'i' } } // Case-insensitive regex search for carModel
          ]
        };
        const products = await productsCollection.find(query).project(projection).sort({ addDate: -1 }).toArray();
        return res.json(products);
      }

      if (req.query.make) query.carBrand = req.query.make;
      if (req.query.model) query.carModel = req.query.model;
      if (req.query.owner) query.ownerSerial = req.query.owner;
      if (req.query.fuel) query.fuelType = req.query.fuel;

      delete query.make
      delete query.model
      delete query.owner
      delete query.fuel

      // Handle mileage range queries
      const kmsDrivenRange = req.query.driven
      if (req.query.year) {
        let year = req.query.year
        year = year.split(',')
        query.year = { $gte: parseInt(year[0].trim()), $lte: parseInt(year[1].trim()) };
      }
      if (kmsDrivenRange) {
        let drivenRange = [];
        if (kmsDrivenRange.includes('-')) {
          drivenRange = kmsDrivenRange.split('-')
        } else if (kmsDrivenRange.includes('<')) {
          drivenRange = kmsDrivenRange.split('<')
          drivenRange[0] = '0'
        }
        if (drivenRange.length === 2) {
          const minMileage = parseInt(drivenRange[0], 10);
          const maxMileage = parseInt(drivenRange[1], 10);
          console.log(minMileage,maxMileage)
          query.kmDriven = { $gte: minMileage, $lte: maxMileage };
        } else {
          // If not a range, assume a single value
          query.kmDriven = parseInt(req.query.driven, 10);
          console.log(query.kmDriven)
        }
        delete query.driven
      }
      // Check if the 'recent' query parameter is present
      if (req.query.recent && req.query.recent.toLowerCase() === 'true') {
        // Add a condition to retrieve recently added products based on the date field (assuming 'addedDate' is the field name)
        const currentDate = new Date();
        const recentDate = new Date(currentDate);
        recentDate.setDate(currentDate.getDate() - 7); // Adjust the number of days as needed
        query.addDate = { $gte: recentDate };
      }
      delete query.start
      console.log(query,'query')
      const products = await productsCollection.find(query).project(projection).sort({ addDate: -1 }).toArray();
      // Check if there are query parameters and return paginated results
      if (Object.keys(req.query).length > 0) {
        const pageSize = 20;
        const end = Math.min(start + pageSize, products.length);
        const paginatedResults = products.slice(start, end);
        // Prepare response with paginated results and next start and end
        const response = {
          results: paginatedResults,
          next: end < products.length ? end : null,
          end: Math.min(end + pageSize, products.length)
        };
        res.json(response);
      } else {
        res.json(products);
      }
    });

    app.get('/recent-products', async (req, res) => {
      let query = { reportStatus: false };
      const requestedNumber = parseInt(req.query.requestedNumber) || 10;
      try {
        const projection = { contactNumber: 0 }; // Exclude contactNumber field
        const products = await productsCollection
          .find(query)
          .project(projection)
          .sort({ timestamp: -1 })
          .limit(requestedNumber)
          .toArray();

        res.json({ success: true, products });
      } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, error: 'Internal Server Error' });
      }
    });

    app.get('/advertise-products', async (req, res) => {
      let query = { adsStatus: "yes", sellStatus: true };
      const products = await productsCollection.find(query).limit(4).sort({ _id: -1 }).toArray();
      res.send(products);
    })

    app.post('/product', verifyJWT, async (req, res) => {
      const product = req.body;
      const result = await productsCollection.insertOne(product);
      res.send(result);
    });

    app.put('/product/:id', verifyJWT, async (req, res) => {
      const productId = req.params.id;
      const updatedProduct = req.body;
      console.log(productId, updatedProduct)

      try {
        // Check if the provided ID is valid
        if (!ObjectId.isValid(productId)) {
          return res.status(400).json({ error: 'Invalid product ID' });
        }

        // Update the product in the database
        const result = await productsCollection.updateOne(
          { _id: ObjectId(productId) },
          { $set: updatedProduct }
        );
        console.log(result)

        if (result.modifiedCount === 0) {
          return res.status(404).json({ error: 'Product not found' });
        }

        res.status(200).json({ message: 'Product updated successfully' });
      } catch (error) {
        console.error('Error updating product:', error);
        res.status(500).json({ error: 'Internal server error' });
      }
    });

    app.get('/product/:id', async (req, res) => {
      const id = req.params.id;
      let query = { _id: ObjectId(id) };
      const product = await productsCollection.findOne(query);
      res.send(product);

    })

    app.get('/category/:slug', async (req, res) => {
      const slug = req.params.slug;
      const categoryQuery = { slug: slug }
      const category = await categoriesCollection.findOne(categoryQuery);
      let query = { category: category.name };
      const products = await productsCollection.find(query).sort({ _id: -1 }).toArray();
      res.send(products);
    })

    app.get('/brand/:slug', async (req, res) => {
      const slug = req.params.slug;
      const brandQuery = { slug: slug }
      const brand = await brandsCollection.findOne(brandQuery);
      let query = { brand: brand.name };
      const products = await productsCollection.find(query).sort({ _id: -1 }).toArray();
      res.send(products);
    })

    app.put('/product/get-ads/:id', verifyJWT, async (req, res) => {
      const id = req.params.id;
      const filter = { _id: ObjectId(id) }
      const options = { upsert: true };
      const udpateData = {
        $set: {
          adsStatus: 'yes'
        }
      }
      const result = await productsCollection.updateOne(filter, udpateData, options)
      res.send(result)
    })

    app.put('/product/remove-ads/:id', verifyJWT, async (req, res) => {
      const id = req.params.id;
      const filter = { _id: ObjectId(id) }
      const options = { upsert: true };
      const udpateData = {
        $set: {
          adsStatus: 'no'
        }
      }
      const result = await productsCollection.updateOne(filter, udpateData, options)
      res.send(result)
    })

    app.delete('/product/:id', verifyJWT, async (req, res) => {
      const id = req.params.id;
      const filter = { _id: ObjectId(id) };
      const result = await productsCollection.deleteOne(filter);
      res.send(result);
    })

    app.get('/my-products', verifyJWT, async (req, res) => {
      const uid = req.query.uid;
      const decodedUID = req.decoded.uid;
      if (uid !== 'all' && uid !== decodedUID) {
        return res.status(403).send({ message: 'forbidden access' });
      }
      const query = { sellerId: uid }
      if (uid === 'all') {
        delete query.sellerId
        query.sellerName = { $ne: 'Admin' };
      }
      const products = await productsCollection.find(query).sort({ timestamp: -1 }).toArray();

      res.send(products);
    })

    app.get('/reported-products', async (req, res) => {
      const query = { reportStatus: true }
      const products = await productsCollection.find(query).toArray();
      res.send(products);
    })

    app.put('/product/report-product/:id/:status', verifyJWT, async (req, res) => {
      const id = req.params.id;
      const filter = { _id: ObjectId(id) }
      let status = req.params.status;
      if (status && status == 'true') {
        status = true
      } else {
        status = false
      }
      const options = { upsert: true };
      const udpateData = {
        $set: {
          reportStatus: status
        }
      }
      const result = await productsCollection.updateOne(filter, udpateData, options)
      res.send(result)
    })

    app.put('/product/change-car-status/:id/:status', verifyJWT, async (req, res) => {
      const id = req.params.id;
      let status = req.params.status;
      if (status && status == 'true') {
        status = true
      } else {
        status = false
      }
      const filter = { _id: ObjectId(id) }
      const options = { upsert: true };
      const udpateData = {
        $set: {
          sellStatus: status
        }
      }
      const result = await productsCollection.updateOne(filter, udpateData, options)
      res.send(result)
    })

    app.put('/product/remove-report/:id', verifyJWT, async (req, res) => {
      const id = req.params.id;
      const filter = { _id: ObjectId(id) }
      const options = { upsert: true };
      const udpateData = {
        $set: {
          reportStatus: false
        }
      }
      const result = await productsCollection.updateOne(filter, udpateData, options)
      res.send(result)
    })

    // USER API
    app.get('/users', async (req, res) => {
      let query = {};
      if (req.query.userType) {
        query = {
          userType: req.query.userType
        }
      }
      const users = await usersCollection.find(query).toArray();
      res.send(users);
    })

    app.get('/user/:id', async (req, res) => {
      const id = req.params.id;
      let query = { uid: id };
      const user = await usersCollection.findOne(query);
      res.send(user);
    })

    app.post('/user', async (req, res) => {
      const email = req.body.email;
      const query = { email }
      const userCheck = await usersCollection.findOne(query);
      if (userCheck) {
        return res.send({ acknowledged: false })
      } else {
        const user = req.body;
        const result = await usersCollection.insertOne(user);
        res.send(result);
      }

    })

    app.put('/user/make-admin/:id', verifyJWT, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const filter = { _id: ObjectId(id) }
      const options = { upsert: true };
      const udpateData = {
        $set: {
          userType: 'admin'
        }
      }
      const result = await usersCollection.updateOne(filter, udpateData, options)
      res.send(result)
    })

    app.put('/user/verify-user/:id', verifyJWT, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const filter = { _id: ObjectId(id) }
      const options = { upsert: true };
      const udpateData = {
        $set: {
          verified: true
        }
      }
      const result = await usersCollection.updateOne(filter, udpateData, options)
      res.send(result)
    })

    app.delete('/user/:id', verifyJWT, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const filter = { _id: ObjectId(id) };
      const result = await usersCollection.deleteOne(filter);
      res.send(result);
    })

    app.get('/brands', async (req, res) => {
      try {
        const query = {};
        const cursor = await brandsCollection.find(query);
        const result = await cursor.toArray();

        // Remove _id from each object
        const resultWithoutId = result.map(obj => {
          delete obj._id;
          return obj;
        });

        res.send(resultWithoutId);
      } catch (error) {
        console.error('Error fetching brands:', error);
        res.status(500).json({ error: 'Internal server error' });
      }
    });

    app.put('/brands-model', verifyJWT, verifyAdmin, async (req, res) => {
      try {
        const newData = req.body;

        // Drop the existing collection
        await brandsAndModel.drop();

        // Insert the new data into the collection
        await brandsAndModel.insertMany(newData);

        res.status(200).json({ message: 'Brands updated successfully' });
      } catch (error) {
        console.error('Error updating brands:', error);
        res.status(500).json({ error: 'Internal server error' });
      }
    });



    app.get('/brands-model', async (req, res) => {
      const query = {}
      const cursor = await brandsAndModel.find(query);
      const result = await cursor.toArray();
      res.send(result)
    })

    app.get('/categories', async (req, res) => {
      const query = {}
      const cursor = await categoriesCollection.find(query);
      const result = await cursor.toArray();
      res.send(result)
    })

    // Booking API
    app.get('/booking', verifyJWT, async (req, res) => {
      const uid = req.query.uid;
      const decodedUID = req.decoded.uid;
      if (uid !== decodedUID) {
        return res.status(403).send({ message: 'forbidden access' });
      }
      const query = { userId: uid }
      const bookings = await bookingCollection.find(query).sort({ _id: -1 }).toArray();
      res.send(bookings);
    })

    app.post('/booking', verifyJWT, async (req, res) => {
      const booking = req.body;
      const query = {
        productId: booking.productId,
        userId: booking.userId
      }

      const alreadyBooked = await bookingCollection.find(query).toArray();

      if (alreadyBooked.length > 0) {
        const message = `Already you have a booking, Check your booking chart!`
        return res.send({ acknowledged: false, message })
      }

      const result = await bookingCollection.insertOne(booking);
      res.send(result);
    })

    app.delete('/booking/:id', verifyJWT, async (req, res) => {
      const id = req.params.id;
      const filter = { _id: ObjectId(id) };
      const result = await bookingCollection.deleteOne(filter);
      res.send(result);
    })

    app.get('/booking/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: ObjectId(id) };
      const booking = await bookingCollection.findOne(query);
      res.send(booking);
    })

    app.post('/create-payment-intent', async (req, res) => {
      const booking = req.body;
      const price = booking.priceAmount;
      const amount = price * 100;

      const paymentIntent = await stripe.paymentIntents.create({
        currency: 'usd',
        amount: amount,
        "payment_method_types": [
          "card"
        ]
      });
      res.send({
        clientSecret: paymentIntent.client_secret,
      });
    });

    app.post('/payments', async (req, res) => {
      const payment = req.body;
      const result = await paymentsCollection.insertOne(payment);
      const id = payment.bookingId
      const filter = { _id: ObjectId(id) }
      const updatedDoc = {
        $set: {
          paymentStatus: true,
          transactionId: payment.transactionId
        }
      }
      const updatedResult = await bookingCollection.updateOne(filter, updatedDoc)

      const productId = payment.productId
      const productFilter = { _id: ObjectId(productId) }
      const updateProduct = {
        $set: {
          sellStatus: false,
        }
      }
      const productUpdated = await productsCollection.updateOne(productFilter, updateProduct)
      res.send(result, updatedResult, productUpdated);
    })


    // Blog API
    app.get('/blogs', async (req, res) => {
      let query = {};
      const blogs = await blogsCollection.find(query).toArray();
      res.send(blogs);
    })

    // JWT Token
    app.post('/jwt', (req, res) => {
      const user = req.body;
      const token = jwt.sign(user, process.env.SECRET_ACCESS_TOKEN, { expiresIn: '1d' })
      res.send({ token })
    })

    app.get('/users/admin/:uid', async (req, res) => {
      const uid = req.params.uid;
      const query = { uid };
      const user = await usersCollection.findOne(query);
      res.send({ isAdmin: user?.userType === 'admin' });
    })

    app.get('/users/seller/:uid', async (req, res) => {
      const uid = req.params.uid;
      const query = { uid };
      const user = await usersCollection.findOne(query);
      res.send({ isSeller: user?.userType === 'seller' });
    })


    app.post('/contact-us', validateContactUs, async (req, res) => {
      try {
        // Validate request body
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
          return res.status(400).json({ success: false, errors: errors.array() });
        }

        const data = req.body;

        // Send acknowledgment email to the user
        const acknowledgmentSubject = `${data.subject} | Arjan Motors`;
        const acknowledgmentBody = `
Dear ${data.fullName},
Thank you for reaching out to us. We've received your inquiry :
Subject: '${data.subject}'.'${data.message}'.
We will get back to you as soon as possible.
Best regards,
The Support Team,
Arjan Motors
https://arjanmotors.in
        `;
        await sendEmail(acknowledgmentSubject, acknowledgmentBody, [data.email]);

        // Forward the inquiry details to a predefined email address
        const forwardSubject = `${data.subject}`;
        const forwardBody = `
New inquiry received!\n\n
From: ${data.fullName} (${data.email}, ${data.contactNumber})\n
Subject: ${data.subject}\n\n
${data.message}
        `;
        const forwardRecipient = 'support@arjanmotors.com';
        const { success } = await sendEmail(forwardSubject, forwardBody, [forwardRecipient]);
        console.log(success, 'axios.post')
        if (success) {
          return res.json({ success: true, message: "We've received your Inquiry." });
        } else {
          return res.status(500).json({ success: false, error: "Something went wrong!" });
        }
      } catch (error) {
        console.log(error)
        return res.status(500).json({ success: false, error: error.message });
      }
    });
  }
  finally {

  }
}
run().catch(err => console.error(err))

app.get('/', (req, res) => {
  res.send('Arjan Motors server is running...')
})

app.listen(port, () => {
  console.log(`Arjan Motors listening on port ${port}`)
})