import csharp

// Find potential cross-site scripting vulnerabilities in ASP.NET code
from MethodCall mc
where mc.getTarget().getName().matches("(Write|Append|Register)ClientScript") or
      mc.getTarget().getName().matches("(Write|Append|Add|Register)StartupScript")
select mc, "Potential cross-site scripting vulnerability"
