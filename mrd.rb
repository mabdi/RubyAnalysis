# IN THE NAME OF ALLAH
#
#
#
#
#
#





############ constants
#file names
FCG_FILENAME = 'mrd_fcg.fuzz'
CFG_PRE = 'mrd_cfg_'
CFG_POST = '.fuzz'
ST_PRE = 'mrd_st_'
ST_POST = '.fuzz'
ET_PRE = 'mrd_et_'
ET_POST = '.fuzz'
RISKS = 'risks'
SYS_FUN = 'frisks'
BRANCHES = 'brancheRisks'
#Risks Code
RREC = "1000"
RLOOP = "1001"
#stt Id
VALLIF = "20"
VALLCALL = "701"

## END OF CONSTANTS
########## Global Variables
@risks = Hash.new	# weights
@frisk = Hash.new	# risk of each function
@srisk = Hash.new	# risk of each Statement
@brisk = Hash.new	# risk of each Branch -- Not If, each If has two branche
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
class Graph
	def add_edge (a,b)
		@edges.push [a,b]
	end
	def initialize
		@edges = Array.new
	end
	def edges
		return @edges
	end
	def n_out s
		return @edges.select { |u,v| u == s }.map {|u,v| v}
	end
	def n_in d
		return @edges.select { |u,v| v == d }.map {|u,v| u}
	end
end
## END OF CLASSES
###############################################################################
############ functions
def d(s)
	puts  ("#{Time.new.strftime("%H:%M:%S")} " + s.to_s).brown.bold
end
def l(n,s)
	space = ""
	n.times{ space = space + "   " }
	puts  ("#{Time.new.strftime("%H:%M:%S")} #{space}" + s.to_s).blue.bold
end
def e(n,s)
	space = ""
	n.times{ space = space + "   " }
	puts  ("#{Time.new.strftime("%H:%M:%S")} #{space}" + s.to_s).red.bold
end
def readWeights
	i=0
	File.open(RISKS).each_line { |line|
		ns = line.split
		@risks[ns[0]] = ns[1].to_i
		i = i+1
	}
	File.open(SYS_FUN).each_line { |line|
		ns = line.split
		@frisk[ns[0]] = ns[1].to_i
		i = i+1
	}
	return i
end
def getFCG
	dg = Graph.new
	i=0
	start = ""
	File.open(FCG_FILENAME).each_line do |line|
		ns = line.split
		dg.add_edge ns[1], ns[2]
		if i == 0 then start = ns[1] end
		i = i+1
	end
return dg,start,i
end
def loadSttType fname
	sttType = Hash.new
	File.open("#{ST_PRE}#{fname}#{ST_POST}").each_line do |line|
		ns = line.split
		sttType[ ns[0]]= ns[1]
	end
	return sttType
end
def loadExpType fname
	expType = Hash.new
	File.open("#{ET_PRE}#{fname}#{ET_POST}").each_line do |line|
		ns = line.split
		expType[ ns[0]]= ns[1] , ns[2]
	end
	return expType

end
def saveResults
	File.open(BRANCHES, 'w') {|f| f.write(@brisk.to_a.map { |k,v| "#{k} #{v}"}.join("\r\n")) }
end
def getCFG fname
	dg = Graph.new
	i=0
	start = ""
	File.open(CFG_PRE + fname + CFG_POST).each_line do |line|
		ns = line.split
		dg.add_edge ns[0], ns[1]
		if i == 0 then start = ns[0] end
		i = i+1
	end
return dg,start,i
end
def sortDAG (s , a , dg , r ,  b)
        b.push s
        nx = dg.n_out s    
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
	l 2,"CFG created successfully. Total #{allins} edges"
	sttType = loadSttType func
	l 2,"Statement types loaded successfully. Total #{sttType.size} statement"
	expType = loadExpType func
	l 2,"Expression types loaded successfully. Total #{expType.size} expression"
	instrs = Array.new
	tmp = Array.new
	loop = Array.new
	sortDAG cfgh,instrs,cfg,loop,tmp
	l 2,"CFG sorted successfully. Total #{instrs.size} Nodes and #{loop.size} loops"
	inum = 0;
	instrs.each do |ins|
		inum = inum +1;
		if inum % 100 == 0 then l 2,"#{inum}/#{instrs.size} statement proceed." end
		@srisk[ins] = @risks[sttType[ins]];
		if loop.include? ins then @srisk[ins] = @srisk[ins] + @risks[RLOOP] end
		if expType.keys.include? ins then
			expType.select { |k,v| k == ins }.values.each do |v|
				@srisk[ins] = @srisk[ins] + @risks[v[0]];
				if v[0] == VALLCALL then
					if @frisk[v[1]].nil? then
						e 3,"Function '#{v[1]}' is not present in frisk"
						abort "Prereqirements not met."
					end
					@srisk[ins] = @srisk[ins] + @frisk[v[1]];
				end
			end
		end
=begin
Note: Action of removing edges that make a cycle in graph. 
Here I suppose that if a child of a node has not processed yet, so its a cycle edge.
I dont know it covers all cases.
a formal proof maybe is needed.
=end
		childs = cfg.edges.select{|u,v| u == ins && !@srisk[v].nil?}.map{|u,v|  [v,@srisk[v]] }
		case sttType[ins]
			when VALLIF
				@srisk[ins] = @srisk[ins] + childs.map{|a| a[1]}.max
				childs.each { |c,r| @brisk[c] = r }
			else
				childs.each{ |c,r| @srisk[ins] = @srisk[ins] + r }
		end
	end
	l 2,"#{inum}/#{instrs.size} statement proceed."
end
def analyse
	l 0,"Start (#{Time.new.strftime("%Y-%m-%d") } #{Time.new.strftime("%H:%M:%S")})"
	allrisk = readWeights
	l 1,"risks loaded successfully, Total #{allrisk} nodes"
	fcg,fcgh,allfuncs = getFCG
	l 1,"FCG created successfully. Total #{allfuncs} edges"
	functions = Array.new
	tmp = Array.new
	recs = Array.new
	sortDAG fcgh,functions,fcg,recs,tmp
	l 1,"FCG sorted successfully. Total #{functions.size} Nodes and #{recs.size} Recurense"
	fnum = 0
	functions.each do |func|
		fnum = fnum + 1
		if @frisk.keys.include? func then
			if File.file? "#{ST_PRE}#{func}#{ST_POST}" then
				e 1,"Anomaly: Function '#{func}' is a system function or a user function that is processed."
				l 2,"We skip this Function '#{func}'"
			end
			next
		else
			if !File.file? "#{ST_PRE}#{func}#{ST_POST}" then
				e 1,"Anomaly: Function '#{func}' is not a system function and not a user function??"
				e 2,"We skip this Function '#{func}'"
				next
			end
		end
		l 1,"Processing Function: #{func} (#{fnum}/#{functions.size})"
		@frisk[func] = 0;
		if recs.include? func then @frisk[func] = @frisk[func] + @risks[RREC] end
		analyseFun func
		l 1,"Function Done: #{func} (#{fnum}/#{functions.size})"
	end
d @brisk
	saveResults
	l 1,"Results saved to file #{BRANCHES}."
	l 0,"Finish at  #{Time.new.strftime("%Y-%m-%d") }"
end
## END OF FUNCTIONS
###############################################################################
########## main
analyse
