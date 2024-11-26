import mongoose from "mongoose";

const connectDB = async () => {
  try {
    const connect = await mongoose.connect(process.env.MONGO_URI);
    console.log(connect.connection.host);
  } catch (error) {
    console.log(error || "Error connecting to Database");
  }
};

export { connectDB };
