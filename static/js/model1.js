document.getElementById("scanForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const domain = document.getElementById("domain").value.trim();
  const res = await fetch("http://127.0.0.1:5000/scan_domain", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domain }),
  });
  const data = await res.json();
  console.log(data);
  alert(`Found ${data.live_subdomains.length} live subdomains`);
});
