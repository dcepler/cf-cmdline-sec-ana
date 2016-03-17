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
		var crlf = chr(13) & chr(10);
		
		cli.write(crlf);
		cli.write("cmdline-security-analyzer.cfm - run ColdFusion 2016 security analyzer from CLI" & crlf);
		cli.write("Copyright (C) 2016 - David C. Epler - dcepler@dcepler.net" & crlf & crlf);
		cli.write("Arguments:" & crlf);
		cli.write("  [username] - username to connect with, default: admin" & crlf);
		cli.write("  password - password to connect with, required" & crlf);
		cli.write("  scanDirectory - directory to scan, required" & crlf);
		cli.write("  [recursive] - scan directories recursively, default: true" & crlf);
		cli.write("  [serverURL] - server URL for service, default: http://127.0.0.1:8500" & crlf);
		cli.write("  [outputDirectory] - output directory, default: current directory" & crlf);
		cli.write("  [outputFilename] - output filename, default: securityanalyzer-yyyymmddhhmmss" & crlf);
		cli.write("  [outputFormat] - json or html, default: html" & crlf);

		cli.write(crlf);
		cli.write("Example:" & crlf);
		cli.write("scanDirectory=c:\inetpub\wwwroot password=myPassword" & crlf);

	}

	public string function generateRDSPostBody(required array parameters) {
		var postBody = arrayLen(arguments.parameters) & ":";
		
		for(var param in arguments.parameters) {
			postBody &= "STR:" & len(param) & ":" & param;
		}
		
		return postBody; 
	}

	// Used strXor() by Peter Day from http://cflib.org/udf/strXOR as basis for function
	// modifed to properly generate XOR'd RDS password from known key
	//
	public string function encryptRDSPassword(required string password) {
		var key = "4p0L@r1$";
		var repeatedKey = left(repeatString(key, ceiling(len(arguments.password) / len(key))), len(arguments.password));
		var encryptedPassword = "";
		
		for (var i = 1; i <= len(arguments.password); i++ ) {
			encryptedPassword &= rJustify(formatBaseN(bitXor(asc(mid(repeatedKey, i, 1)), asc(mid(arguments.password, i, 1))), 16), 2);
		}
		
		return lCase(binaryEncode(binaryDecode(replaceNoCase(encryptedPassword, " ", "0", "all"), "hex"), "hex"));
	}

	//
	variables.securityAnalyzerQueryString = "/CFIDE/main/ide.cfm?CFSRV=IDE&ACTION=SECURITYANALYZER";
	variables.userAgent = "Mozilla/3.0 (compatible; Macromedia RDS Client)";
	variables.requestTimeout = 600;
	
	variables.currentWorkingDirectory = replace(getCurrentTemplatePath(), "\", "/", "all");
	variables.currentWorkingDirectory = replace(variables.currentWorkingDirectory, listLast(variables.currentWorkingDirectory, "/"), "");


	// populate from arguments
	variables.username = cli.getNamedArg("username")?: "admin";
	variables.password = cli.getNamedArg("password");
	variables.scanDirectory = cli.getNamedArg("scanDirectory");
	variables.recursive = cli.getNamedArg("recursive")?: "true";
	variables.serverURL = cli.getNamedArg("serverURL")?: "http://127.0.0.1:8500";
	variables.outputDirectory = cli.getNamedArg("outputDirectory")?: variables.currentWorkingDirectory;
	variables.outputFilename = cli.getNamedArg("outputFilename")?: "securityanalyzer-" & dateTimeFormat(now(), "yyyymmddHHnnss");
	variables.outputFormat = cli.getNamedArg("outputFormat")?: "html";

	// show help information if no args or first arg is "help"
	if (arrayIsEmpty(cli.getArgs()) || findNoCase("help", cli.getArg(1))) {
		generateHelp();
		cli.exit(0);
	}

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
		// verify scan directory exists
	}

	if (!isBoolean(variables.recursive)) {
		cli.writeError("ERROR: recursive must be true or false");
		generateHelp();
		cli.exit(-1);
	}

	variables.outputDirectory = replace(variables.outputDirectory, "\", "/", "all");
	// verify outputDirectory exists

	if (!ListFindNoCase("html,json", variables.outputFormat)) {
		cli.writeError("ERROR: outputFormat must be html or json");
		generateHelp();
		cli.exit(-1);
	}
	variables.outputFormat = lCase(variables.outputFormat);
	
	// build POST body for RDS request
	variables.postBody = generateRDSPostBody([variables.scanDirectory, variables.recursive, variables.username, encryptRDSPassword(variables.password)]);

	variables.scanStart = getTickCount();
	
	// execute RDS request for security analyzer
	try {
		cfhttp(method="POST", charset="utf-8", url=variables.serverURL & variables.securityAnalyzerQueryString, result="variables.rdsResult", userAgent=variables.userAgent, timeout=variables.requestTimeout) {
	    	cfhttpparam(type="body", value=variables.postBody);
		}
	}
	catch (any excpt) {
		cli.writeError("Error connecting to security analyzer");
		writeDump(var=excpt, format="text");
		cli.exit(-2);
	}
	// more processing of result needs to happen
	//
	// connection failure
	// Connection Failure
	//
	// auth failure
	// -100:Unable to authenticate on RDS server using current security information.
	
	variables.scanDuration = (getTickCount() - variables.scanStart) / 1000;
	
	variables.jsonResult = mid(variables.rdsResult.fileContent, find("{", variables.rdsResult.fileContent), (len(variables.rdsResult.fileContent) - find("{", variables.rdsResult.fileContent) + 1));

	switch(variables.outputFormat) {
		case "json":
			fileWrite(variables.outputDirectory & variables.outputFilename & "." & variables.outputFormat, variables.jsonResult);
			break;
		case "html":
			variables.htmlReport = fileRead(variables.currentWorkingDirectory & "report-template.html");
			
			variables.htmlReport = replace(variables.htmlReport, "{$securityAnalyzerResult}", variables.jsonResult);
			variables.htmlReport = replace(variables.htmlReport, "{$reportDate}", now().dateTimeFormat("full"));
			variables.htmlReport = replace(variables.htmlReport, "{$scanDirectory}", variables.scanDirectory);
			variables.htmlReport = replace(variables.htmlReport, "{$scanDuration}", variables.scanDuration & " seconds");
			fileWrite(variables.outputDirectory & variables.outputFilename & "." & variables.outputFormat, variables.htmlReport);
			break;
		default:
		
	}

// writeDump(var=variables, format="text");
</cfscript>
