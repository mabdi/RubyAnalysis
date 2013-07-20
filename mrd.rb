require 'rgl/base'
require 'rgl/adjacency'
#require 'rgl/mutable'
#require 'rgl/dot'
#require 'rgl/connected_components'

############ constants
FCG_FILENAME = 'mrd_fcg.fuzz'
CFG_PRE = 'mrd_cfg_'
CFG_POST = '.fuzz'
ST_PRE = 'mrd_st_'
ST_POST = '.fuzz'
ET_PRE = 'mrd_et_'
ET_POST = '.fuzz'
RISKS = 'risks'
#Risks Code
RRec = 0;
RLoop = 0;


## END OF CONSTANTS
########## Global Variables
risks = Hash.new	# weights
frisk = Hash.new	# risk of each function
srisk = Hash.new	# risk of each Statement
brisk = Hash.new	# risk of each Branch -- Not If, each If has two branche
## END OF VARIABLES
####################################################
############ classes
class String
def black;          "\033[30m#{self}\033[0m" end
def red;            "\033[31m#{self}\033[0m" end
def green;          "\033[32m#{self}\033[0m" end
def  brown;         "\033[33m#{self}\033[0m" end
def blue;           "\033[34m#{self}\033[0m" end
def magenta;        "\033[35m#{self}\033[0m" end
def cyan;           "\033[36m#{self}\033[0m" end
def gray;           "\033[37m#{self}\033[0m" end
def bg_black;       "\033[40m#{self}\0330m"  end
def bg_red;         "\033[41m#{self}\033[0m" end
def bg_green;       "\033[42m#{self}\033[0m" end
def bg_brown;       "\033[43m#{self}\033[0m" end
def bg_blue;        "\033[44m#{self}\033[0m" end
def bg_magenta;     "\033[45m#{self}\033[0m" end
def bg_cyan;        "\033[46m#{self}\033[0m" end
def bg_gray;        "\033[47m#{self}\033[0m" end
def bold;           "\033[1m#{self}\033[22m" end
def reverse_color;  "\033[7m#{self}\033[27m" end
end

## END OF CLASSES
###############################################################################
############ functions
def l(n,s)
	space = ""
	n.time{ space = space + "   " }
	puts  ("#{Time.new.strftime("%H:%M:%S")}: #{space}" + s.to_s).blue.bold
end
def readWeights
	i=0
	File.open(RISKS).each_line do |line|
		ns = line.split
		risks[ns[1]] = ns[2].to_i
		i = i+1
	end
	return i
end
def getFCG
	dg = RGL::DirectedAdjacencyGraph[]
	i=0
	start = ""
	File.open(FCG_FILENAME).each_line do |line|
		ns = line.split
		dg.add_edge ns[1], ns[2]
		if i == 0 then start = ns[0]
		i = i+1
	end
return dg,start,i
end
def loadSttType fname

end
def loadExpType fname

end
def saveResults

end
def getCFG fname
	dg = RGL::DirectedAdjacencyGraph[]
	i=0
	start = ""
	File.open(CFG_PRE + fname + CFG_POST).each_line do |line|
		ns = line.split
		dg.add_edge ns[0], ns[1]
		if i == 0 then start = ns[0]
		i = i+1
	end
return dg,start,i
end
def sortDAG (s , a , dg , r ,  b)
        b.push s
        nx = dg.edges.select { |e| e.source == s }.map {|e| e.target}
        nx.each { |n|
                if a.include? n then next end
                if b.include? n  then
                        r.push s
                        next
                end
                sortDAG n , a , dg , r , b
        }
        a.push s
        b.pop
end
def analyseFun func
	cfg,cfgh,allins = getCFG func
	l 2,"CFG created successfully. Total #{allins} edges";
	sttType = loadSttType func
	l 2,"Statement types loaded successfully. Total #{sttType.size} statement";
	expType = loadExpType func
	l 2,"Expression types loaded successfully. Total #{expType.size} expression";
	instrs = Array.new
	tmp = Array.new
	loop = Array.new
	sortDAG cfgh,instrs,cfg,loops,tmp
	l 2,"CFG sorted successfully. Total #{instrs.size} Nodes and #{loops.size} loops";
	inum = 1;
	instrs.each { |ins|
		if inum % 100 == 0 then l 2,"#{inum}/#{instrs.size} statement proceed."
		srisk[ins] = risk[sttType[ins]];
		if loops.includes? ins then srisk[ins] = srisk[ins] + risk[RLoop] end
		if expType.keys.includes? ins) then
			expType.select { |k,v| k == ins }.map {|k,v| v}.each{ |v|
				srisk[ins] = risk[sttType[v]];
			}
		end
	}
	l 2,"#{inum}/#{instrs.size} statement proceed."
end
def analyse
	l 0,"Start at  #{Time.new.strftime("%Y-%m-%d") }"
	allrisk = readWeights
	l 1,"risks loaded successfully, Total #{allrisk} nodes";
	fcg,fcgh,allfuncs = getFCG
	l 1,"FCG created successfully. Total #{allfuncs} edges";
	functions = Array.new
	tmp = Array.new
	recs = Array.new
	sortDAG fcgh,functions,fcg,recs,tmp
	l 1,"FCG sorted successfully. Total #{functions.size} Nodes and #{recs.size} Recurense";
	fnum = 1;
	functions.each { |func|
		l 1,"Processing Function: #{func} (#{fnum}/#{func.size})";
		frisk[func] = 0;
		if recs.includes? func then frisk[func] = frisk[func] + risk[RRec] end
		analyseFun func
		l 1,"Function Done: #{func}";
	}
	l 1,"Processing Function: #{func} (#{fnum}/#{func.size})";
	saveResults
	l 1,"Results saved to file.";
	l 0,"Finish at  #{Time.new.strftime("%Y-%m-%d") }"
end
## END OF FUNCTIONS
###############################################################################
########## main
analyse
