set terminal png nocrop enhanced size 1600,1200 font "arial,28"
unset key
set datafile separator ","
set output outfile
set style line 1 lc rgb '#0060ad' lt 1 lw 2 pt 7 ps 1

set xlabel 'iteration'
set ylabel 'number of nodes in routing table'
set grid

plot input using 0:2 with points ls 1
