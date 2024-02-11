import { Request, Response } from "express";
import { storeInstance } from "../middlewares/session";
import { MongoClient } from "mongodb";

export const deleteSession = async (req: Request, res: Response) => {
  const sessionId = req.sessionID;

  // Destroy Session
  req.session.destroy((err) => {
    if (err) {
      console.log(err);
      return res.status(500).send("Error destroying session");
    }

    // Delete session from MongoDB database using storeInstance
    storeInstance.destroy(sessionId, (err) => {
      if (err) {
        console.log(err);
        return res.status(500).send("Error deleting session from database");
      }
      console.log("Session deleted from database");
    });
  });
};

export const clearExpiredSessions = async () => {
  try {
    const client = await MongoClient.connect(process.env.DB_URL!);
    const db = client.db();
    const collection = db.collection("sessions");
    const now = new Date();

    await collection.deleteMany({ expires: { $lt: now } });
    console.log("Expired sessions cleared successfully.");
    client.close();
  } catch (error) {
    console.error("Error clearing expired sessions:", error);
  }
};
