import express, { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";

interface UserData {
  id: string;
  name: string;
  address: string;
}

interface ValidationRequest extends Request {
  userData: UserData;
}

export const accessValidation = (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  const validationReq = req as ValidationRequest;
  const { authorization } = validationReq.headers;

  if (!authorization) {
    return res.status(401).json({
      message: "Token is needed",
    });
  }

  const token = authorization.split(" ")[1];
  const jwt_secret = process.env.JWT_SECRET!;

  try {
    const jwtDecode = jwt.verify(token, jwt_secret);
    if (typeof jwtDecode !== "string") {
      validationReq.userData = jwtDecode as UserData;
    }
  } catch (error) {
    return res.status(401).json({
      message: "Unauthorized",
    });
  }

  next();
};
