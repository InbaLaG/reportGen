const express = require('express');
const config = require('config');
const router = express.Router();
const path = require('path');
const dateFormat = require('dateformat');
const async = require('async');
const http = require('http');
const fs = require('fs-extra');
const debug = require('debug')('reportgenerator1:report');
const md5File = require('md5-file')
const mime = require('mime');
const os = require('os');
const random = require('random-world');
//a json object describing malware and several types for each
//this info taken from http://www.malwaretruth.com/the-list-of-malware-types/,
// https://www.kaspersky.com/resource-center/threats/malware-classifications, https://www.mcafee.com/threat-intelligence/malware/latest.aspx
//and wikipedia
const malware={
    "Adware":{
        "description": "The least dangerous and most lucrative Malware. Adware displays ads on your computer.",
        "types":["advertisements","monitor servers"],
        "samples:":["1ClickDownloader","7search"]
    },
    "Spyware":{
        "description":"Spyware is software that spies on you, tracking your internet activities in order to send advertising (Adware) back to your system.",
        "types":["CoolWebSearch","FinFisher","HuntBar","DyFuCa","Look2Me","WeatherStudio"]
    },
    "Virus":{
        "description":"A virus is a contagious program or code that attaches itself to another piece of software, and then reproduces itself when that software is run. Most often this is spread by sharing software or files between computers.",
        "types":["Win32","Generic", ],
        "samples":["Generic.e!71CDC3201116","W32/Virut.n.gen!2CFCEBA94166","W32/Sality.gen!2DA507C2B243" ]
    },
    "Worm":{
        "description":"A program that replicates itself and destroys data and files on the computer. Worms work to “eat” the system operating files and data files until the drive is empty.",
        "types" : ["Email-Worm","IM-Worm","IRC-Worm","Net-Worm","P2P-Worm","Virus"]
    },
    "Trojan":{
        "description":"The most dangerous Malware. Trojans are written with the purpose of discovering your financial information, taking over your computer’s system resources, and in larger systems creating a “denial-of-service attack ” Denial-of-service attack: an attempt to make a machine or network resource unavailable to those attempting to reach it. Example: AOL, Yahoo or your business network becoming unavailable.",
        "types":["Backdoor","Exploit","Rootkit","Trojan-Banker","Trojan-DDoS","Trojan-Downloader","Trojan-Dropper","Trojan-FakeAV","Trojan-GameThief","Trojan-IM","Trojan-Ransom","Trojan-SMS","Trojan-Spy"]
    },
    "Rootkit":{
        "description":"This one is likened to the burglar hiding in the attic, waiting to take from you while you are not home. It is the hardest of all Malware to detect and therefore to remove; many experts recommend completely wiping your hard drive and reinstalling everything from scratch. It is designed to permit the other information gathering Malware in to get the identity information from your computer without you realizing anything is going on.",
        "types":["Library Rootkits","Kernel Rootkits","Application Rootkits"],
        "samples":["Lane Davis and Steven Dake", "NTRootkit","HackerDefender","Machiavelli","Greek wiretapping","Zeus","Stuxnet","Flame"]
    },
    "Backdoors":{
        "description":"Backdoors are much the same as Trojans or worms, except that they open a “backdoor” onto a computer, providing a network connection for hackers or other Malware to enter or for viruses or SPAM to be sent.",
        "types":["Worms","Object code backdoors","Asymmetric backdoors"]
    },
    "Keyloggers":{
        "description":"Records everything you type on your PC in order to glean your log-in names, passwords, and other sensitive information, and send it on to the source of the keylogging program. Many times keyloggers are used by corporations and parents to acquire computer usage information.  ",
        "types":["Hypervisor-based","Kernel-based","API-based","javascript-based","Memory injection based"]
    },
    "Rogue security software":{
        "description": "This one deceives or misleads users. It pretends to be a good program to remove Malware infections, but all the while it is the Malware. Often it will turn off the real Anti-Virus software. The next image shows the typical screen for this Malware program, Antivirus 2010",
        "types": ["Black Hat SEO","Spam Comments",]
    },
    "Ransomware":{
        "description":"If you see this screen that warns you that you have been locked out of your computer until you pay for your cybercrimes. Your system is severely infected with a form of Malware called Ransomware. It is not a real notification from the FBI, but, rather an infection of the system itself. Even if you pay to unlock the system, the system is unlocked, but you are not free of it locking you out again. The request for money, usually in the hundreds of dollars is completely fake.",
        "types":["Leakware (also called Doxware)","Mobile ransomware","Non-encrypting ransomware","Encrypting ransomware"],
        "samples":["Reveton","CryptoLocker","CryptoWall"]
    },
    "Browser Hijacker":{
        "description":"When your homepage changes to one that looks like those in the images inserted next, you may have been infected with one form or another of a Browser Hijacker. This dangerous Malware will redirect your normal search activity and give you the results the developers want you to see. Its intention is to make money off your web surfing. Using this homepage and not removing the Malware lets the source developers capture your surfing interests. This is especially dangerous when banking or shopping online. These homepages can look harmless, but in every case they allow other more infectious ",
        "types":["Ask Toolbar","Babylon Toolbar","Conduit (Search Protect)/Trovi","CoolWebSearch","Coupon Server","GoSave","istartsurf","Mixi.DJ"]
    }
};
//Private functions
function createHtmlreport(req, uploadedFile, callback) {

    async.waterfall([

        //get file properties from fs
        function(callback){

            var fileProperties = {};

            fs.stat(uploadedFile, function(err, stats) {
                if(err){
                    callback(err);
                }

                fileProperties.filesize = stats["size"];
                fileProperties.filemode = stats["mode"];
                fileProperties.filedatecreated = stats["ctime"].toString();
                //console.log(JSON.stringify(fileProperties));
                callback (null, fileProperties);
            });

        },
        //get file properties from other various sources
        function(fileProperties,callback){

            fileProperties.filename=req.files.file_path.name;
            fileProperties.filemd5 = md5File.sync(uploadedFile);
            fileProperties.filetype = mime.lookup(uploadedFile);
            fileProperties.filehostanalizer = os.hostname() + " | " + os.platform() + " | " + os.arch();
            callback(null, fileProperties)
        },
        //file arrived from... (fake info)
        function(fileProperties,callback){
            var optionalChannels = ["Email attachment", "External disk hard copy", "Sent to a bluetuth device","Spam Emails","Manipulated SEO rankings"];
            fileProperties.filesource = optionalChannels[Math.floor(Math.random()*optionalChannels.length)]
            callback(null,fileProperties);
        },
        //file appearance in the world info (fake data)
        function(fileProperties,callback){

            //generage a csv file with countries and numbers
            var cList='country,appearance\n';
            for (var i = 0; i < config.report.barchartSize; i++) {
                cList += random.country().replace(/,/g,"") + ',' + Math.floor(Math.random()*20000).toString() + '\n';
            }

            // var csvFile = path.join( process.env.PWD, "public", "data", path.basename(uploadedFile, path.extname(uploadedFile))+".csv");
            // console.log(csvFile)
            // console.log(config.server.barchartSize)
            // for (var i = 0; i < 30; i++) {
            //     cList.push([random.country().replace(/,/g,""),Math.floor(Math.random()*20000)]);
            // }
            // console.log(JSON.stringify(cList));
            // fs.writeFile(
            //     csvFile,
            //     cList.map(function(data){ return data.join(',') }).join('\n'),
            //     function (err) {
            //         if (err) {
            //             callback(err)
            //         }
            //     }
            // );
            fileProperties.filebarchartdata = cList;

            callback(null,fileProperties);
        },
        //What did the file do once executed (fake printscreen GIF)
        function(fileProperties,callback){
            fs.readdir(path.join( process.env.PWD,"public","GIF"),function (err, files)  {
                if(err){
                    callback(err);
                }
                var file = files[Math.floor(Math.random()*files.length)];
                fileProperties.filegiflink = "http://" + config.server.serverName.toString() + ":" + config.server.port.toString() + "/GIF/"+file;
                callback(null,fileProperties);
            });

        },
        //Classify the file: Malwares are coming from different families and types, try to represent it graphically J
        // (Hint: read about malware families and Malware types to get the idea)
        function(fileProperties,callback){
            var malicousList=[];
            var chosenType=Object.keys(malware).length;
            for (key in malware) {
                malicousList.push({
                    y: Math.floor(Math.random()*1000),
                    legendText: key,
                    indexLabel: key,
                    description:malware[key].description,
                    exploded: false});

            }
             malicousList[Math.floor(Math.random()*malicousList.length)].exploded = true;
            fileProperties.filePieChartData=JSON.stringify(malicousList).replace(/"(\w+)"\s*:/g, '$1:');

            callback(null,fileProperties);
        },
        //create Html report with all the data
        function(fileProperties,callback){
            fs.readFile(path.join( process.env.PWD, "templates", "report.html"), 'utf8', function (err, htmlSource) {
                if (err) {
                    callback(err);
                }

                for (key in fileProperties){
                    if (typeof(fileProperties[key]) !== "object"){
                        htmlSource = htmlSource.replace(new RegExp("#" + key + "#","gi"), fileProperties[key]);
                    }

                }
                callback(null,htmlSource);
            });

        }
    ], function (error, success) {
        if (error) {
            callback (error);
        }
        callback (error, success);

    });
}

//Public functions
router.post('/', function(req, res) {

    const dlFolder = path.join( process.env.PWD, config.server.downloadsLocation || "downloads");
    const rptFolder = path.join( process.env.PWD, config.server.reportsLocation || "reports");
    const currentDate=dateFormat(new Date(), "dd_mm_yyyy_h_MM_ssTT");

    if (!Object.keys(req.files).length){
        debug('No files were uploaded.');
        return res.status(400).send('No files were uploaded.');
    }

    const rptFile=path.join( rptFolder, currentDate + "_" + req.files.file_path.name + ".html");

    //Create required folders if needed
    if(!fs.existsSync(dlFolder))
        fs.mkdirSync(dlFolder);

    if(!fs.existsSync(rptFolder))
        fs.mkdirSync(rptFolder);
    const uploadedFileName = path.join(dlFolder,currentDate + "_" + req.files.file_path.name);

    req.files.file_path.mv(uploadedFileName, function(err) {
        if (err)
            return res.status(500).send(err);

        //generating the report source code
        async.waterfall([
            function(callback){
                createHtmlreport(req, uploadedFileName,callback);
            },
            //creating the file report
            function(hSrc, callback){
                fs.writeFileSync(rptFile, hSrc);
                callback(null);
            }
        ], function (error, success) {
            if (error) {
                res.status(500).send(err);
            }
            res.setHeader('Content-disposition', 'attachment; filename=' + path.basename(rptFile));
            res.setHeader('Content-Type', 'text/html');
            res.download(rptFile, function(err){
                if (err) {
                    return res.status(400).send('Error occurred while downloading the report file');
                } else {

                }
            });
            // res.download(rptFile);
           // res.sendFile(path.basename(rptFile), {root: rptFolder});
           //  res.redirect('back');
            // res.setHeader('Content-disposition', 'attachment; filename=' + path.basename(rptFile));
            // res.setHeader('Content-Type', 'text/html');
            // res.send('File ' + req.files.file_path.name + ' uploaded...');
        });

    });
});

module.exports = router;
