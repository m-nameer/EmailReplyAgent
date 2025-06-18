import axios from "axios";


const API_URL = "https://2803-39-48-219-229.ngrok-free.app"
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
