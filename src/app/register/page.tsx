"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api";

export default function RegisterPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [error, setError] = useState("");
  const router = useRouter();

  const handleRegister = async () => {
    try {
      console.log("Credentials: ", email, password, name)
      console.log("api: ",api)
      await api().post("/register", { email, password, name });
      router.push("/login");
    } catch (err: unknown) {
      // setError(err.response?.data?.detail || "Registration failed");
      const error = err as { response?: { data?: { detail?: string } } };
      setError(error.response?.data?.detail || "Registration failed");
    }
  };

  return (
    <div className="p-8 max-w-md mx-auto">
      <h1 className="text-2xl mb-4">Register</h1>
      {error && <p className="text-red-500">{error}</p>}
      <input
        className="border p-2 w-full mb-2"
        placeholder="Name"
        onChange={(e) => setName(e.target.value)}
      />
      <input
        className="border p-2 w-full mb-2"
        placeholder="Email"
        onChange={(e) => setEmail(e.target.value)}
      />
      <input
        className="border p-2 w-full mb-4"
        type="password"
        placeholder="Password"
        onChange={(e) => setPassword(e.target.value)}
      />
      <button className="bg-blue-600 text-white px-4 py-2" onClick={handleRegister}>
        Register
      </button>
    </div>
  );
}
