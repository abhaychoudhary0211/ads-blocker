module.exports = async function handler(req, res) {
  res.status(200).json({
    name: "My AdBlocker",
    status: "online"
  });
};
