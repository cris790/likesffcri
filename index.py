export default function handler(req, res) {
  const { uid, key } = req.query;

  if (key !== "22") {
    return res.status(403).json({ error: "Chave inválida" });
  }

  res.status(200).json({
    name: "!Bruno333ㅤッ",
    uid,
    region: "BR",
    level: 78,
    likes_before: 114982,
    likes_after: 114982,
    likes_added: 0,
    failed_likes: 97,
  });
}

