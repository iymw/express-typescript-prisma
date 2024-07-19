import express, { NextFunction, Request, Response } from "express";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { accessValidation } from "./accessValidation";

const app = express();
const prisma = new PrismaClient();
const PORT = 5000;

app.use(express.json());

// REGISTER
app.use("/register", async (req, res) => {
  const { name, email, address, password } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);
  const result = await prisma.users.create({
    data: {
      name,
      email,
      address,
      password: hashedPassword,
    },
  });
  res.json({ data: result, message: "user created" });
});

// LOGIN
app.use("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await prisma.users.findUnique({
    where: {
      email: email,
    },
  });

  if (!user || !user?.password) {
    return res.status(404).json({
      message: "user not found",
    });
  }

  const isPasswordValid = await bcrypt.compare(password, user?.password);

  if (isPasswordValid) {
    const payload = {
      id: user.id,
      name: user.name,
      address: user.address,
    };

    const jwt_secret = process.env.JWT_SECRET!;
    const countdown = 60 * 60 * 1;
    const token = jwt.sign(payload, jwt_secret, { expiresIn: countdown });

    return res.json({
      data: payload,
      token: token,
    });
  } else {
    return res.status(403).json({
      message: "Wrong password",
    });
  }
});

// CREATE
app.post("/users", async (req, res, next) => {
  const { name, email, address } = req.body;
  const result = await prisma.users.create({
    data: {
      name: name,
      email: email,
      address: address,
    },
  });
  res.json({ data: result, message: "user created" });
});

// READ
app.get("/users", accessValidation, async (req, res, next) => {
  const result = await prisma.users.findMany({
    select: {
      id: true,
      name: true,
      email: true,
      address: true,
    },
  });
  res.json({ data: result, message: "users lists" });
});

// UPDATE
app.patch("/users/:id", async (req, res, next) => {
  const { id } = req.params;
  const { name, email, address } = req.body;
  const result = await prisma.users.update({
    data: {
      name: name,
      email: email,
      address: address,
    },
    where: {
      id: Number(id),
    },
  });
  res.json({ data: result, message: `User ${id} updated` });
});

// DELETE
app.delete("/users/:id", async (req, res, next) => {
  const { id } = req.params;
  const result = await prisma.users.delete({
    where: {
      id: Number(id),
    },
  });
  res.json({ message: `User ${id} deleted` });
});

app.listen(PORT, () => {
  console.log(`Server running in PORT: ${PORT}`);
});
