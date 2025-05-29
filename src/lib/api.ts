import axios from "axios";


const API_URL = "http://localhost:8000"
// const API_URL = "https://d53a-124-29-232-126.ngrok-free.app"

export const api = (token?: string) =>
  axios.create({
    baseURL: API_URL,
    withCredentials: true,
    headers: token
      ? {
          Authorization: `Bearer ${token}`,
        }
      : {},
  });
