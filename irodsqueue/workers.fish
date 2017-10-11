for i in (seq 16)
	sleep .1; rq worker -v --burst -w irodsworker.IrodsWorker high normal low &
end
