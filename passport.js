
function Passport()
{

}
Passport.run = function()
{
	var source = require("./passport_source.js");
	source.start();	
}

Passport.run();