"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api";

export default function DashboardPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [whatsappQR, setWhatsappQR] = useState("");
  const [gmailConnected, setGmailConnected] = useState(false);
  const [agentEnabled, setAgentEnabled] = useState(false);
  const [loading, setLoading] = useState(true); // ⏳
  // const [authenticated, setAuthenticated] = useState(false); // ✅

  useEffect(() => {
    const fetchData = async () => {
      try {
        const userRes = await api().get("/me");
        setEmail(userRes.data.email);
        // setAuthenticated(true);

        const agentRes = await api().get("/agent/status");
        setAgentEnabled(agentRes.data.enabled);

        const gmailRes = await api().get("/email/status");
        setGmailConnected(gmailRes.data.connected);
      } catch (err) {
        console.error("Not authenticated", err);
        router.push("/login");
      } finally {
        setLoading(false);
      }
    };

    fetchData();

    const handleMessage = (event: MessageEvent) => {
      // ✅ Accept origin from backend (where popup runs)
      if (
        event.origin === "http://localhost:8000" &&
        event.data?.type === "gmail_connected"
      ) {
        api()
          .get("/email/status")
          .then((res) => setGmailConnected(res.data.connected));
      }
    };

    window.addEventListener("message", handleMessage);

    return () => {
      window.removeEventListener("message", handleMessage);
    };
  }, [router]);


  const connectGmail = async () => {
    const res = await api().get("/email/authorize");
    // const popup = window.open(res.data.auth_url, "_blank", "width=500,height=600");
    window.open(res.data.auth_url, "_blank", "width=500,height=600");

  };

  const connectWhatsApp = async () => {
  setWhatsappQR(""); // Clear any old QR
  const res = await api().get("/whatsapp/connect");

  if (res.data.status === "need_scan") {
    setWhatsappQR(res.data.qr);

    // Start polling status every 5s up to 60s
    let waited = 0;
    const interval = setInterval(async () => {
      const statusRes = await api().get("/whatsapp/status");
      if (statusRes.data.status === "connected") {
        clearInterval(interval);
        setWhatsappQR("");
        alert("✅ WhatsApp connected!");
      }
      waited += 5;
      if (waited >= 60) clearInterval(interval);
    }, 5000);
  } else if (res.data.status === "connected") {
    alert("✅ WhatsApp is already connected!");
    setWhatsappQR("");
  }
};

  const toggleAgent = async () => {
    const res = await api().post("/agent/toggle", {
      enabled: !agentEnabled,
    });
    setAgentEnabled(res.data.enabled);
  };

  const disconnectGmail = async () => {
    try {
      await api().post("/email/disconnect");
      setGmailConnected(false);
      alert("Gmail disconnected.");
    } catch (err) {
      console.error("Failed to disconnect Gmail", err);
      alert("Error disconnecting Gmail.");
    }
  };



  const disconnectWhatsApp = async () => {
  try {
    await api().post("/whatsapp/disconnect");
    alert("❌ WhatsApp disconnected.");
    setWhatsappQR("");
  } catch (err) {
    console.error("Failed to disconnect WhatsApp", err);
    alert("Error disconnecting WhatsApp.");
  }
};




  if (loading) return <div className="p-8">Loading...</div>;

  return (
    <div className="p-8">
      <h1 className="text-xl mb-4">Dashboard</h1>
      <p>Logged in as: <strong>{email}</strong></p>

      <div className="mt-6 space-y-4">
        <div>
          <button onClick={connectGmail} className="bg-blue-600 text-white px-4 py-2">
            {gmailConnected ? "Reconnect Gmail" : "Connect Gmail"}
          </button>
          <p className="text-sm mt-1">{gmailConnected ? "✅ Gmail Connected" : "❌ Gmail Not Connected"}</p>

          {gmailConnected && (
            <button
              onClick={disconnectGmail}
              className="bg-red-500 text-white px-4 py-2 mt-2"
            >
              Disconnect Gmail
            </button>
          )}
        </div>

        <div>
          <button onClick={connectWhatsApp} className="bg-green-600 text-white px-4 py-2">
            Connect WhatsApp
          </button>
          {whatsappQR && (
            <div className="mt-2">
              <p>Scan this QR in WhatsApp:</p>
              <img src={`https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=${encodeURIComponent(whatsappQR)}`} alt="WhatsApp QR code"/>
            </div>
          )}

          {!whatsappQR && (
            <button
              onClick={disconnectWhatsApp}
              className="bg-red-500 text-white px-4 py-2 mt-2"
            >
              Disconnect WhatsApp
            </button>
          )}

        </div>

        <div>
          <button onClick={toggleAgent} className="bg-purple-600 text-white px-4 py-2">
            {agentEnabled ? "Stop Agent" : "Start Agent"}
          </button>
          <p className="text-sm mt-1">
            {agentEnabled ? "✅ Agent is Active" : "⚠️ Agent is Disabled"}
          </p>
        </div>

        <button className="bg-red-600 text-white px-4 py-2 mt-6" onClick={() => {
          document.cookie = "access_token=; Max-Age=0"; // clear cookie
          router.push("/login");
        }}>
          Logout
        </button>
      </div>
    </div>
  );
}
