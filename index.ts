
import definePlugin from "@utils/types";

export default definePlugin({
    name: "DiscordOpsec",
    description: "Privacy and security tools for Discord",
    authors: [
        {
            name: "Seekehr",
            id: 535439695849455629n
        }
    ],

    start() {
        console.log("[DiscordOpsec] Plugin started successfully!");
    },

    stop() {
        console.log("[DiscordOpsec] Plugin stopped!");
    }
});
