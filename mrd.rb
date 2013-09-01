# IN THE NAME OF ALLAH
#
#
#
#
#
#

require 'mrdbg'
require 'consolor'


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
BMAP = 'mrd_branches_mapping'
#Risks Code
RREC = '1000'
RLOOP = '1001'
#stt Id
VALLIF = "20"
VALLCALL = "701"


## END OF CONSTANTS
########## Global Variables
@risks = Hash.new	# weights
@frisk = Hash.new	# risk of each function
@srisk = Hash.new	# risk of each Statement
@brisk = Hash.new	# risk of each Branch -- Not If, each If has two branche
@bmap = Hash.new	# mapping from InstrId to bId
@anomals = Array.new	# function names that is not in frisk function
## END OF VARIABLES
####################################################
############ classes
class Graph
	def add_edge (a,b)
		@nodes.push a unless @nodes.include? a
		@nodes.push b unless @nodes.include? b
		@edges.push [a,b]
	end
	def initialize
		@nodes = Array.new
		@edges = Array.new
	end
	def size
		return @nodes.size
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
	def has? x
		return @edges.flatten.include? x
	end
	def to_dot fname
		strdot = "digraph mrd {\n"
		@nodes.each{|n| strdot = "#{strdot}\n    #{n} [\n        fontsize = 8,\n        label = #{n}\n    ]\n" }
		@edges.each{|a,b| strdot = "#{strdot}\n    #{a} -> #{b} [\n        fontsize = 8\n    ]\n"}
		strdot = "#{strdot}\n}"
		File.open("#{fname}.dot", 'w') {|f| f.write(strdot) }
	end
	def heads
		hs = Array.new
		@nodes.each{ |n|
			hs.push (n) if @edges.select{|u,v| v == n}.size == 0
		}
		return hs
	end
	def head
		hs = heads
		abort("No or more than one Head in graph") unless hs.size == 1
		return hs[0]
	end
	def tails
                ts = Array.new
                @nodes.each{ |n|
                        ts.push (n) if @edges.select{|u,v| u == n}.size == 0
                }
                return ts          
        end
        def tail
		ts = tails
                abort("No or more than one Head in graph") unless ts.size == 1
                return ts[0]
        end
end
## END OF CLASSES
###############################################################################
############ functions
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
def readBmap
        i=0
        File.open(BMAP).each_line { |line|
                ns = line.split
                @bmap[ns[0]] = ns[1].to_i
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
		i = i+1
	end
	if dg.has? "main" then start = "main" else e 2,"No 'main' node exists."; abort "Exiting..." end
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
	readBmap
	File.open(BRANCHES, 'w') {|f| f.write(@brisk.to_a.map { |k,v| "#{@bmap[k]} #{v}"}.join("\r\n")) }
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
def sortDAG (startNode , sorted , graph , r ,  b)
        b.push startNode
        nx = graph.n_out startNode   
        nx.each { |n|
                if sorted.include? n then next end
                if b.include? n  then
                        r.push startNode
                        next
                end
                sortDAG n , sorted , graph , r , b
        }
        sorted.push startNode
        b.pop
end
def analyseFun func
	retVal=0
	cfg,cfgh,allins = getCFG func
	@m.l 2,"CFG created successfully. Total #{allins} edges"
	sttType = loadSttType func
	@m.l 2,"Statement types loaded successfully. Total #{sttType.size} statement"
	expType = loadExpType func
	@m.l 2,"Expression types loaded successfully. Total #{expType.size} expression"
	instrs = Array.new
	tmp = Array.new
	loop = Array.new
	sortDAG cfgh,instrs,cfg,loop,tmp
	(@m.e 0, "size mismatches .... #{func} ";cfg.to_dot "cfg_#{func}") if cfg.size != instrs.size
	@m.l 2,"CFG sorted successfully. Total #{instrs.size} Nodes and #{loop.size} loops"
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
						@m.e 3,"Function '#{v[1]}' is not present in frisk"
						abort "Prereqirements not met."
					end
					@srisk[ins] = @srisk[ins] + @frisk[v[1]];
				end
			end
		end
=begin
Note: Action of removing edges that make a cycle in graph. 
Here I suppose that if a child of a node has not processed yet, so its a cycle edge.
I dont know it covers all cases. because we scan down to top a sorted list.
a formal proof maybe is needed.
=end
		childs = cfg.edges.select{|u,v| u == ins && !@srisk[v].nil?}.map{|u,v|  [v,@srisk[v]] }
		case sttType[ins]
			when VALLIF
				@srisk[ins] = @srisk[ins] + childs.map{|a| a[1]}.max
				childs.each { |c,r| @brisk[c] = r;@temp.push "#{ins} #{c}" }
			else
				childs.each{ |c,r| @srisk[ins] = @srisk[ins] + r }
		end
		retVal = @srisk[ins];
	end
	@m.l 2,"#{inum}/#{instrs.size} statement proceed."
 	return retVal
end
@temp = Array.new
@m = Mrdbg.new
def analyse
	@m.l 0,"Start (#{Time.new.strftime("%Y-%m-%d") } #{Time.new.strftime("%H:%M:%S")})"
	allrisk = readWeights
	@m.l 1,"risks loaded successfully, Total #{allrisk} nodes"
	fcg,fcgh,allfuncs = getFCG
	@m.l 1,"FCG created successfully. Total #{allfuncs} edges"
	functions = Array.new
	tmp = Array.new
	recs = Array.new
	sortDAG fcgh,functions,fcg,recs,tmp
        (@m.e 0, "FCG size mismatches ....  ";fcg.to_dot "fcg") if fcg.size != functions.size
	@m.l 1,"FCG sorted successfully. Total #{functions.size} Nodes and #{recs.size} Recurense"
#@m.b binding
	fnum = 0
	functions.each do |func|
		fnum = fnum + 1
		if @frisk.keys.include? func then
			if File.file? "#{ST_PRE}#{func}#{ST_POST}" then
				@m.e 1,"Anomaly: Function '#{func}' is a system function or a user function that is processed."
				@m.l 2,"We skip this Function '#{func}'"
				@anomals.push func
			end
			next
		else
			if !File.file? "#{ST_PRE}#{func}#{ST_POST}" then
				@m.e 1,"Anomaly: Function '#{func}' is not a system function and not a user function??"
				@m.e 2,"We skip this Function '#{func}'"
				@anomals.push func
				next
			end
		end
		@m.l 1,"Processing Function: #{func} (#{fnum}/#{functions.size})"
		@frisk[func] = 0;
		if recs.include? func then @frisk[func] = @frisk[func] + @risks[RREC] end
		@frisk[func] = @frisk[func] + analyseFun func
		@m.l 1,"Function Done: #{func} (#{fnum}/#{functions.size})"
	end
#@m.d @brisk
(@m.d @anomals.each{|s| puts "#{s} 1"}) if (!ARGV[0].nil? && (ARGV[0].include? 'a'))
	saveResults
@m.b (binding) if @dbg
	@m.l 1,"Results saved to file #{BRANCHES}."
	@m.l 0,"Finish at  #{Time.new.strftime("%Y-%m-%d") }"
end
## END OF FUNCTIONS
###############################################################################
########## main
@dbg = (!ARGV[0].nil? && (ARGV[0].include? 'd'))
analyse
