<!---
	cmdline-security-analyzer.cfm - run ColdFusion 2016 security analyzer from CLI
	Copyright (C) 2016 - David C. Epler - dcepler@dcepler.net

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
--->
<cfscript>

	public void function generateHelp() {
		
		cli.writeln("");
		cli.writeln("cmdline-security-analyzer.cfm - run ColdFusion 2016 security analyzer from CLI");
		cli.writeln("Copyright (C) 2016 - David C. Epler - dcepler@dcepler.net");
		cli.writeln("");
		cli.writeln("Arguments:");
		cli.writeln("  [username] - username to connect with, default: admin");
		cli.writeln("  password - password to connect with, required");
		cli.writeln("  scanDirectory - directory to scan, required");
		cli.writeln("  [recursive] - scan directories recursively, default: true");
		cli.writeln("  [serverURL] - server URL for service, default: http://127.0.0.1:8500");
		cli.writeln("  [pollDelay] - polling wait time in milliseconds, default: 1000");
		cli.writeln("  [outputDirectory] - output directory, default: current directory");
		cli.writeln("  [outputFilename] - output filename, default: securityanalyzer-yyyymmddhhmmss");
		cli.writeln("  [outputFormat] - json or html, default: html");
		cli.writeln("");
		cli.writeln("  *** Requires ColdFusion 2016 Update 2 or higher ***");
		cli.writeln("");
		cli.writeln("Example:");
		cli.writeln("scanDirectory=c:\inetpub\wwwroot password=myPassword");
	}

	// Used strXor() by Peter Day from http://cflib.org/udf/strXOR as basis for function
	// modifed to properly generate XOR'd RDS password from known key
	//
	private string function encryptRDSPassword(required string password) {
		var key = "4p0L@r1$";
		var repeatedKey = left(repeatString(key, ceiling(len(arguments.password) / len(key))), len(arguments.password));
		var encryptedPassword = "";
		
		for (var i = 1; i <= len(arguments.password); i++ ) {
			encryptedPassword &= rJustify(formatBaseN(bitXor(asc(mid(repeatedKey, i, 1)), asc(mid(arguments.password, i, 1))), 16), 2);
		}
		
		return lCase(binaryEncode(binaryDecode(replaceNoCase(encryptedPassword, " ", "0", "all"), "hex"), "hex"));
	}

	private string function generateRDSPostBody(required array parameters) {
		var postBody = arrayLen(arguments.parameters) & ":";
		
		for(var param in arguments.parameters) {
			postBody &= "STR:" & len(param) & ":" & param;
		}
		
		return postBody; 
	}

	private string function sendRDSPost(required string serverURL, required string securityAnalyzerQueryString, required string userAgent, required string postBody, numeric requestTimeout=60) {
	
		var rdsResult = "";

		// execute RDS request for security analyzer
		try {
			cfhttp(method="POST", charset="utf-8", url=arguments.serverURL & arguments.securityAnalyzerQueryString, result="rdsResult", userAgent=arguments.userAgent, timeout=arguments.requestTimeout) {
		    	cfhttpparam(type="body", value=arguments.postBody);
			}
		}
		catch (any exception) {
			rethrow; 
		}
		
		// authentication failure
		if (findNoCase("-100:Unable to authenticate on RDS server using current security information", rdsResult.fileContent)) {
			throw(type="sendRDSPost", message="ERROR: Invalid username and/or password for RDS server", detail=rdsResult.errorDetail, errorCode=-2); 
		}
	
		// connection failure
		if (findNoCase("Connection Failure", rdsResult.fileContent)) {
			throw(type="sendRDSPost", message="ERROR: Connection failure", detail=rdsResult.errorDetail, errorCode=-2); 
		}

		return mid(rdsResult.fileContent, find("{", rdsResult.fileContent), (len(rdsResult.fileContent) - find("{", rdsResult.fileContent) + 1));
		
	}

	public string function executeSecurityAnalyzer(required string scanDirectory, required string recursive, required string username, required string password, numeric pollDelay=1000, required string serverURL, required string securityAnalyzerQueryString, required string userAgent, numeric requestTimeout=60) {
		
		// generate encrypted password once since used multiple times
		var encryptedPassword = encryptRDSPassword(arguments.password);
		
		var jsonString = "";
		var jsonResultString = "";
		var scanResult = "";
		var postBody = "";
		
		// status tracking of scan
		var id = 0;
		var percentageComplete = 0;

		// generate scan command to start scan
		try {
			postBody = generateRDSPostBody(["SCAN", arguments.scanDirectory, arguments.recursive, arguments.username, encryptedPassword]);
			jsonString = sendRDSPost(arguments.serverURL, arguments.securityAnalyzerQueryString, arguments.userAgent, postBody, arguments.requestTimeout);
		}
		catch (any exception) {
			rethrow;
		}

		// convert JSON to ColdFusion variables
		scanResult = deserializeJSON(jsonString, true);
		
		if (structKeyExists(scanresult,"errormessage") && findnocase("Security Code Analyzer is not available in this edition of the ColdFusion Server",scanresult.errormessage)){
			throw(type="wrongVersion", message="ERROR: wrong CF edition", detail="#scanresult.errormessage#", errorCode=-2); 
		}

		// populate id needed for subsequent commands
		id = scanResult["id"];

		// generate status command until reports 100% complete
		while (percentageComplete != 100) {

			try {
				postBody = generateRDSPostBody(["STATUS", id, arguments.username, encryptedPassword]);
				jsonString = sendRDSPost(arguments.serverURL, arguments.securityAnalyzerQueryString, arguments.userAgent, postBody, arguments.requestTimeout);
			}
			catch (any exception) {
				rethrow;
			}

			scanResult = deserializeJSON(jsonString, true);

			// update percentage
			percentageComplete = scanResult["percentage"];
			
			// delay net status poll for delay time
			sleep(arguments.pollDelay);
			
		}

		// generate result command to get full results
		try {
			postBody = generateRDSPostBody(["RESULT", id, arguments.username, encryptedPassword]);
			jsonResultString = sendRDSPost(arguments.serverURL, arguments.securityAnalyzerQueryString, arguments.userAgent, postBody, arguments.requestTimeout);
		}
		catch (any exception) {
			rethrow;
		}

		// generate clean command to cleanup security analyzer processes
		try {
			postBody = generateRDSPostBody(["CLEAN", id, arguments.username, encryptedPassword]);
			jsonString = sendRDSPost(arguments.serverURL, arguments.securityAnalyzerQueryString, arguments.userAgent, postBody, arguments.requestTimeout);
		}
		catch (any exception) {
			rethrow;
		}
		
		return jsonResultString;
		
 	}

	public string function generateVulnerabilityTable(required struct data){
		var tableData = "";
		
		for (var item in arguments.data.errors) {
			tableData &= "<tr><td>" & item.path & "</td><td>" & item.Error & "</td><td>" & item.type & "</td><td>" & item.beginline & "</td><td>" & item.begincolumn & "</td><td>" & (structKeyExists(item, "vulnerablecode")? item.vulnerablecode : "") & "</td></tr>";
		}
		
		return tableData;		
	}
	
	public string function generateUnscanableTable(required struct data){
		var tableData = "";
		
		for (var item in arguments.data.filesnotscanned) {
			tableData &= "<tr><td>" & item.filename & "</td><td>" & item.reason &"</td></tr>";
		}
		
		return tableData;		
	}

	// constants
	variables.securityAnalyzerQueryString = "/CFIDE/main/ide.cfm?CFSRV=IDE&ACTION=SECURITYANALYZER";
	variables.userAgent = "Mozilla/3.0 (compatible; Macromedia RDS Client)";
	variables.requestTimeout = 60;
	variables.now = now();
	
	// determine current working directory
	variables.currentWorkingDirectory = replace(getCurrentTemplatePath(), "\", "/", "all");
	variables.currentWorkingDirectory = replace(variables.currentWorkingDirectory, listLast(variables.currentWorkingDirectory, "/"), "");

	// populate from arguments
	variables.username = cli.getNamedArg("username")?: "admin";
	variables.password = cli.getNamedArg("password");
	variables.scanDirectory = cli.getNamedArg("scanDirectory");
	variables.recursive = cli.getNamedArg("recursive")?: "true";
	variables.serverURL = cli.getNamedArg("serverURL")?: "http://127.0.0.1:8500";
	variables.pollDelay = cli.getNamedArg("pollDelay")?: 1000;
	variables.outputDirectory = cli.getNamedArg("outputDirectory")?: variables.currentWorkingDirectory;
	variables.outputFilename = cli.getNamedArg("outputFilename")?: "securityanalyzer-" & variables.now.dateTimeFormat("yyyymmddHHnnss");
	variables.outputFormat = cli.getNamedArg("outputFormat")?: "html";

	// show help information if no args or first arg is "help"
	if (arrayIsEmpty(cli.getArgs()) || findNoCase("help", cli.getArg(1))) {
		generateHelp();
		cli.exit(0);
	}

	// version check to ensure can properly communicate with security analyzer via RDS
	if ((val(listGetAt(server.coldfusion.productVersion, 1)) != 2016) && (val(listGetAt(server.coldfusion.productVersion, 3)) < 2)) {
		cli.writeError("ERROR: Incorrect version of ColdFusion Server, must be ColdFusion 2016 Update 2 or greater");
		cli.exit(-3);
	}

	// TODO: remote version check from [serverURL]/CFIDE/adminapi/administrator.cfc?method=getBuildNumber

	// validate arguments
	if (!structKeyExists(variables, "password")) {
		cli.writeError("ERROR: password is required");
		generateHelp();
		cli.exit(-1);
	}

	if (!structKeyExists(variables, "scanDirectory")) {
		cli.writeError("ERROR: scanDirectory is required");
		generateHelp();
		cli.exit(-1);
	} else {
		variables.scanDirectory = replace(variables.scanDirectory, "\", "/", "all");
		// TODO: verify scan directory exists
	}

	if (!isBoolean(variables.recursive)) {
		cli.writeError("ERROR: recursive must be true or false");
		generateHelp();
		cli.exit(-1);
	}

	variables.outputDirectory = replace(variables.outputDirectory, "\", "/", "all");
	// TODO: verify outputDirectory exists

	if (!ListFindNoCase("html,json", variables.outputFormat)) {
		cli.writeError("ERROR: outputFormat must be html or json");
		generateHelp();
		cli.exit(-1);
	}
	variables.outputFormat = lCase(variables.outputFormat);

	if (!IsValid("integer", variables.pollDelay)) {
		cli.writeError("ERROR: pollDelay must be an integer");
		generateHelp();
		cli.exit(-1);
	}

	if (variables.pollDelay < 250) {
		cli.writeError("ERROR: pollDelay must be larger than 250 milliseconds");
		generateHelp();
		cli.exit(-1);
	}
	variables.pollDelay = int(variables.pollDelay);
	
	// execute security analyzer
	variables.scanStart = getTickCount();

	try {
		variables.jsonResult = executeSecurityAnalyzer(variables.scanDirectory, variables.recursive, variables.username, variables.password, variables.pollDelay, variables.serverURL, variables.securityAnalyzerQueryString, variables.userAgent, variables.requestTimeout);
	}
	catch (any exception) {
		cli.writeError(exception.message);
		cli.exit(exception.errorCode);
	}
	
	variables.scanDuration = (getTickCount() - variables.scanStart) / 1000;
	variables.scanResult = deserializeJSON(variables.jsonResult, true);

	// generate report
	switch(variables.outputFormat) {
		case "json":
			fileWrite(variables.outputDirectory & variables.outputFilename & "." & variables.outputFormat, variables.jsonResult);
			break;
		case "html":
			variables.htmlReport = fileRead(variables.currentWorkingDirectory & "report-template.html");
			
			variables.htmlReport = replace(variables.htmlReport, "${securityAnalyzerResult}", variables.jsonResult);
			variables.htmlReport = replace(variables.htmlReport, "${reportDate}", variables.now.dateTimeFormat("full"));
			variables.htmlReport = replace(variables.htmlReport, "${scanDirectory}", variables.scanDirectory);
			variables.htmlReport = replace(variables.htmlReport, "${scanDuration}", variables.scanDuration & " seconds");
			variables.htmlReport = replace(variables.htmlReport, "${vulnerabilityList}", generateVulnerabilityTable(variables.scanResult));
			variables.htmlReport = replace(variables.htmlReport, "${unscanableList}", generateUnscanableTable(variables.scanResult));
			
			fileWrite(variables.outputDirectory & variables.outputFilename & "." & variables.outputFormat, variables.htmlReport);
			break;
		default:
		
	}

	cli.writeln("Scan Compelete - " & variables.now.dateTimeFormat("full"));
	cli.writeln(repeatString("-", 72));
	cli.writeln("Scan Directory .: " & variables.scanDirectory);
	cli.writeln("Scan Durarion ..: " & variables.scanDuration & " seconds");
	cli.writeln("Report File ....: " & variables.outputDirectory & variables.outputFilename & "." & variables.outputFormat);
	cli.writeln(repeatString("-", 72));
	
	// writeDump(var=variables.scanResult, format="text");
	
	cli.exit(0);

</cfscript>
