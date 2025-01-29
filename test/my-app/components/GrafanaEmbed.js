import React from "react";

const GrafanaEmbed = () => {
  return (
    <div className="grafana-container">
      <iframe
        src="http://localhost:3000/d/app/netprobe?orgId=1&from=2025-01-27T15:27:23.807Z&to=2025-01-27T15:57:23.807Z&timezone=browser"
        width="100%"
        height="600px"
        frameBorder="0"
        title="Grafana Dashboard"
      ></iframe>
    </div>
  );
};

export default GrafanaEmbed;
