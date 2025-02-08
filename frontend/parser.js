const fs = require('fs').promises;
const path = require('path');

const dataDir = path.join(__dirname, 'data'); 

async function readJsonFiles(directory) {
    const staticPath = path.join(directory, 'static_report.json');
    const dynamicPath = path.join(directory, 'dyanamic_report.json');

    let data = {};

    try {
        if (await fileExists(staticPath)) {
            const staticData = await fs.readFile(staticPath, 'utf8');
            data.static = JSON.parse(staticData);
        } else {
            console.log(`Warning: ${staticPath} not found`);
        }

        if (await fileExists(dynamicPath)) {
            console.log(1211111111111111111111)
            const dynamicData = await fs.readFile(dynamicPath, 'utf8');
            data.dynamic = JSON.parse(dynamicData);
        } else {
            console.log(`Warning: ${dynamicPath} not found`);
        }
    } catch (error) {
        console.error(`Error reading JSON files in ${directory}:`, error);
    }

    return data;
}

// Helper function to check file existence asynchronously
async function fileExists(filePath) {
    try {
        await fs.access(filePath);
        return true;
    } catch {
        return false;
    }
}

async function Parser() {
    let full = {};

    try {
        const directories = await fs.readdir(dataDir);
        for (const dir of directories) {
            const dirPath = path.join(dataDir, dir);
            const stat = await fs.lstat(dirPath);

            if (stat.isDirectory()) {
                const jsonData = await readJsonFiles(dirPath);
                full[dir] = jsonData;
            }
        }
        console.log(JSON.stringify(full))
        return full;
    } catch (err) {
        console.error('Error reading data directory:', err);
        return {};
    }
}
Parser()
module.exports = { Parser };
